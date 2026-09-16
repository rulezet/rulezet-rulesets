rule TTP_XOR_WriteProcessMemory_3849 {
  strings:
    $key_3849 = { 6f 3b [2] 5d 19 [2] 5b 2c [2] 75 2c [2] 4a 30 }

  condition:
    any of them
}