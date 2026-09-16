rule TTP_XOR_WriteProcessMemory_4869 {
  strings:
    $key_4869 = { 1f 1b [2] 2d 39 [2] 2b 0c [2] 05 0c [2] 3a 10 }

  condition:
    any of them
}