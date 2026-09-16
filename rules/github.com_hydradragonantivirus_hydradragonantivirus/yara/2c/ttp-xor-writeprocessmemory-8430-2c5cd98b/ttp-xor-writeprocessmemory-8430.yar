rule TTP_XOR_WriteProcessMemory_8430 {
  strings:
    $key_8430 = { d3 42 [2] e1 60 [2] e7 55 [2] c9 55 [2] f6 49 }

  condition:
    any of them
}