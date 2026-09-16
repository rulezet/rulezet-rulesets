rule TTP_XOR_WriteProcessMemory_84dc {
  strings:
    $key_84dc = { d3 ae [2] e1 8c [2] e7 b9 [2] c9 b9 [2] f6 a5 }

  condition:
    any of them
}