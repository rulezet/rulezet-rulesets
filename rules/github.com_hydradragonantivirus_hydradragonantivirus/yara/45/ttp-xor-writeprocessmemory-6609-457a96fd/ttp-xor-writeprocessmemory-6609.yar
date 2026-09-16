rule TTP_XOR_WriteProcessMemory_6609 {
  strings:
    $key_6609 = { 31 7b [2] 03 59 [2] 05 6c [2] 2b 6c [2] 14 70 }

  condition:
    any of them
}