rule TTP_XOR_WriteProcessMemory_4d29 {
  strings:
    $key_4d29 = { 1a 5b [2] 28 79 [2] 2e 4c [2] 00 4c [2] 3f 50 }

  condition:
    any of them
}