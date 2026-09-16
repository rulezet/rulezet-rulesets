rule TTP_XOR_WriteProcessMemory_27dc {
  strings:
    $key_27dc = { 70 ae [2] 42 8c [2] 44 b9 [2] 6a b9 [2] 55 a5 }

  condition:
    any of them
}