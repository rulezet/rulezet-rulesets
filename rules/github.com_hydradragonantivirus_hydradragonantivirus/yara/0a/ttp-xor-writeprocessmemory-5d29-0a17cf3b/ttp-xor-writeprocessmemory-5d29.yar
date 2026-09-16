rule TTP_XOR_WriteProcessMemory_5d29 {
  strings:
    $key_5d29 = { 0a 5b [2] 38 79 [2] 3e 4c [2] 10 4c [2] 2f 50 }

  condition:
    any of them
}