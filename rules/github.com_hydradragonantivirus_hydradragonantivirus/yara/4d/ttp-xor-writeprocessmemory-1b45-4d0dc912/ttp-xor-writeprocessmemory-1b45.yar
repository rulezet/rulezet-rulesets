rule TTP_XOR_WriteProcessMemory_1b45 {
  strings:
    $key_1b45 = { 4c 37 [2] 7e 15 [2] 78 20 [2] 56 20 [2] 69 3c }

  condition:
    any of them
}