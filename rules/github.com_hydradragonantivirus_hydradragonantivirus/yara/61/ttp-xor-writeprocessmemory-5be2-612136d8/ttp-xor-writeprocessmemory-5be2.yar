rule TTP_XOR_WriteProcessMemory_5be2 {
  strings:
    $key_5be2 = { 0c 90 [2] 3e b2 [2] 38 87 [2] 16 87 [2] 29 9b }

  condition:
    any of them
}