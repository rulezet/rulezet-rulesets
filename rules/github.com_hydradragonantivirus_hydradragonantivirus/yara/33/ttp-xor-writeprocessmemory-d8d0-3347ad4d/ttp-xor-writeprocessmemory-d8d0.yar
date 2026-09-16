rule TTP_XOR_WriteProcessMemory_d8d0 {
  strings:
    $key_d8d0 = { 8f a2 [2] bd 80 [2] bb b5 [2] 95 b5 [2] aa a9 }

  condition:
    any of them
}