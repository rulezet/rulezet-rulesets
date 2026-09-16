rule TTP_XOR_WriteProcessMemory_0b22 {
  strings:
    $key_0b22 = { 5c 50 [2] 6e 72 [2] 68 47 [2] 46 47 [2] 79 5b }

  condition:
    any of them
}