rule TTP_XOR_WriteProcessMemory_0be2 {
  strings:
    $key_0be2 = { 5c 90 [2] 6e b2 [2] 68 87 [2] 46 87 [2] 79 9b }

  condition:
    any of them
}