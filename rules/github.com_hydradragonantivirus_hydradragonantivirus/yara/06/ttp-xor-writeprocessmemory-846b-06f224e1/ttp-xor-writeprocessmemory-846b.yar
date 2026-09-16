rule TTP_XOR_WriteProcessMemory_846b {
  strings:
    $key_846b = { d3 19 [2] e1 3b [2] e7 0e [2] c9 0e [2] f6 12 }

  condition:
    any of them
}