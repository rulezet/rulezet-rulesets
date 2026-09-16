rule TTP_XOR_WriteProcessMemory_d8da {
  strings:
    $key_d8da = { 8f a8 [2] bd 8a [2] bb bf [2] 95 bf [2] aa a3 }

  condition:
    any of them
}