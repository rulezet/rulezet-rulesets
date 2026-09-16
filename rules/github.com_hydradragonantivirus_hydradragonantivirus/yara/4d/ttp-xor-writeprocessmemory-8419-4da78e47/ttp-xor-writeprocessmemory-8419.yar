rule TTP_XOR_WriteProcessMemory_8419 {
  strings:
    $key_8419 = { d3 6b [2] e1 49 [2] e7 7c [2] c9 7c [2] f6 60 }

  condition:
    any of them
}