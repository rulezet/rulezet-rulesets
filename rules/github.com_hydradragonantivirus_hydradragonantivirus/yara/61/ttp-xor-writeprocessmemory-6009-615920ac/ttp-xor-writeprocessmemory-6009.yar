rule TTP_XOR_WriteProcessMemory_6009 {
  strings:
    $key_6009 = { 37 7b [2] 05 59 [2] 03 6c [2] 2d 6c [2] 12 70 }

  condition:
    any of them
}