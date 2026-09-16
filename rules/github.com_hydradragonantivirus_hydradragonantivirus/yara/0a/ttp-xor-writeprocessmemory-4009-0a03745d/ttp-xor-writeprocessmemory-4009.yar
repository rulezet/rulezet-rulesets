rule TTP_XOR_WriteProcessMemory_4009 {
  strings:
    $key_4009 = { 17 7b [2] 25 59 [2] 23 6c [2] 0d 6c [2] 32 70 }

  condition:
    any of them
}