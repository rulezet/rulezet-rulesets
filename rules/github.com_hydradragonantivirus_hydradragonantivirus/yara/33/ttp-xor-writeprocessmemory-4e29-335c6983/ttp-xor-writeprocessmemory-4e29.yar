rule TTP_XOR_WriteProcessMemory_4e29 {
  strings:
    $key_4e29 = { 19 5b [2] 2b 79 [2] 2d 4c [2] 03 4c [2] 3c 50 }

  condition:
    any of them
}