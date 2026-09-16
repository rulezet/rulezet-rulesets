rule TTP_XOR_WriteProcessMemory_840e {
  strings:
    $key_840e = { d3 7c [2] e1 5e [2] e7 6b [2] c9 6b [2] f6 77 }

  condition:
    any of them
}