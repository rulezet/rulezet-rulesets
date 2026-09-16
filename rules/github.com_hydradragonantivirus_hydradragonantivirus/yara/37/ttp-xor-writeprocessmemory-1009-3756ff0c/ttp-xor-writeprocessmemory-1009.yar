rule TTP_XOR_WriteProcessMemory_1009 {
  strings:
    $key_1009 = { 47 7b [2] 75 59 [2] 73 6c [2] 5d 6c [2] 62 70 }

  condition:
    any of them
}