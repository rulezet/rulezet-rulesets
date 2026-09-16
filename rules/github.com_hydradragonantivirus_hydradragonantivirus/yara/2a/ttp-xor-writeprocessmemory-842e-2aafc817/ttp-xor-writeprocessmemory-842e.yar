rule TTP_XOR_WriteProcessMemory_842e {
  strings:
    $key_842e = { d3 5c [2] e1 7e [2] e7 4b [2] c9 4b [2] f6 57 }

  condition:
    any of them
}