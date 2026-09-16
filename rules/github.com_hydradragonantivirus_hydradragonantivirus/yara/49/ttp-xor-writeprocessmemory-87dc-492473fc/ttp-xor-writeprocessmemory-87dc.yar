rule TTP_XOR_WriteProcessMemory_87dc {
  strings:
    $key_87dc = { d0 ae [2] e2 8c [2] e4 b9 [2] ca b9 [2] f5 a5 }

  condition:
    any of them
}