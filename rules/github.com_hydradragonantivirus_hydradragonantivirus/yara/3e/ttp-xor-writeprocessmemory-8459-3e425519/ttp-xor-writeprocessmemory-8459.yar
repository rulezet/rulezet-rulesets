rule TTP_XOR_WriteProcessMemory_8459 {
  strings:
    $key_8459 = { d3 2b [2] e1 09 [2] e7 3c [2] c9 3c [2] f6 20 }

  condition:
    any of them
}