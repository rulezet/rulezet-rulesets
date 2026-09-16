rule TTP_XOR_WriteProcessMemory_da29 {
  strings:
    $key_da29 = { 8d 5b [2] bf 79 [2] b9 4c [2] 97 4c [2] a8 50 }

  condition:
    any of them
}