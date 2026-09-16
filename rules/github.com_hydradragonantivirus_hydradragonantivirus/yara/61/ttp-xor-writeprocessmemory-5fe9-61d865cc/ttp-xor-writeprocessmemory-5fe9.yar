rule TTP_XOR_WriteProcessMemory_5fe9 {
  strings:
    $key_5fe9 = { 08 9b [2] 3a b9 [2] 3c 8c [2] 12 8c [2] 2d 90 }

  condition:
    any of them
}