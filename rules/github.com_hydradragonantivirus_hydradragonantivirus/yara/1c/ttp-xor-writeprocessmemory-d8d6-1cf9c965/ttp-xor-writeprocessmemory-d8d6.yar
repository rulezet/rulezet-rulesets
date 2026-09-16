rule TTP_XOR_WriteProcessMemory_d8d6 {
  strings:
    $key_d8d6 = { 8f a4 [2] bd 86 [2] bb b3 [2] 95 b3 [2] aa af }

  condition:
    any of them
}