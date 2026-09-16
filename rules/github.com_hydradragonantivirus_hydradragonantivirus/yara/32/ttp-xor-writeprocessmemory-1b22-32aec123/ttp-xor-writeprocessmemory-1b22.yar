rule TTP_XOR_WriteProcessMemory_1b22 {
  strings:
    $key_1b22 = { 4c 50 [2] 7e 72 [2] 78 47 [2] 56 47 [2] 69 5b }

  condition:
    any of them
}