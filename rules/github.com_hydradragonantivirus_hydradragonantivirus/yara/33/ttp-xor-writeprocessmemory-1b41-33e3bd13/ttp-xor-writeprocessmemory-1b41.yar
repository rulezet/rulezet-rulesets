rule TTP_XOR_WriteProcessMemory_1b41 {
  strings:
    $key_1b41 = { 4c 33 [2] 7e 11 [2] 78 24 [2] 56 24 [2] 69 38 }

  condition:
    any of them
}