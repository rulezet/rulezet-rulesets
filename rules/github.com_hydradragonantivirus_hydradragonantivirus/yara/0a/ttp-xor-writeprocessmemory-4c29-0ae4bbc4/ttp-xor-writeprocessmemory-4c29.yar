rule TTP_XOR_WriteProcessMemory_4c29 {
  strings:
    $key_4c29 = { 1b 5b [2] 29 79 [2] 2f 4c [2] 01 4c [2] 3e 50 }

  condition:
    any of them
}