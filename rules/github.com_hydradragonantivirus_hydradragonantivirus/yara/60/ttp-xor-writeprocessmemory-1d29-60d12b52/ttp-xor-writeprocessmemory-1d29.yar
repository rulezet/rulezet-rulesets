rule TTP_XOR_WriteProcessMemory_1d29 {
  strings:
    $key_1d29 = { 4a 5b [2] 78 79 [2] 7e 4c [2] 50 4c [2] 6f 50 }

  condition:
    any of them
}