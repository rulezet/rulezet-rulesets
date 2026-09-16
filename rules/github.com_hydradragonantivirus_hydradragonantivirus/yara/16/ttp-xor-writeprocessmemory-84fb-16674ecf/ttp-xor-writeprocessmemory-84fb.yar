rule TTP_XOR_WriteProcessMemory_84fb {
  strings:
    $key_84fb = { d3 89 [2] e1 ab [2] e7 9e [2] c9 9e [2] f6 82 }

  condition:
    any of them
}