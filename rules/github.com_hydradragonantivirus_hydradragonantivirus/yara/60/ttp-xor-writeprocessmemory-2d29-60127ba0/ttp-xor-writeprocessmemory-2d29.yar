rule TTP_XOR_WriteProcessMemory_2d29 {
  strings:
    $key_2d29 = { 7a 5b [2] 48 79 [2] 4e 4c [2] 60 4c [2] 5f 50 }

  condition:
    any of them
}