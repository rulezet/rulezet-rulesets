rule TTP_XOR_WriteProcessMemory_daf9 {
  strings:
    $key_daf9 = { 8d 8b [2] bf a9 [2] b9 9c [2] 97 9c [2] a8 80 }

  condition:
    any of them
}