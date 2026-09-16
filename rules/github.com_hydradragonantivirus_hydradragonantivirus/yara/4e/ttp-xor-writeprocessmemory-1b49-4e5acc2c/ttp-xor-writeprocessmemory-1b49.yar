rule TTP_XOR_WriteProcessMemory_1b49 {
  strings:
    $key_1b49 = { 4c 3b [2] 7e 19 [2] 78 2c [2] 56 2c [2] 69 30 }

  condition:
    any of them
}