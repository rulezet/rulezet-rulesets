rule TTP_XOR_WriteProcessMemory_4809 {
  strings:
    $key_4809 = { 1f 7b [2] 2d 59 [2] 2b 6c [2] 05 6c [2] 3a 70 }

  condition:
    any of them
}