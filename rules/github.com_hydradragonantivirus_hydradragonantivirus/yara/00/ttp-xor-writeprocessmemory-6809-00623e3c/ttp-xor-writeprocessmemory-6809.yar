rule TTP_XOR_WriteProcessMemory_6809 {
  strings:
    $key_6809 = { 3f 7b [2] 0d 59 [2] 0b 6c [2] 25 6c [2] 1a 70 }

  condition:
    any of them
}