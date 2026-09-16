rule TTP_XOR_WriteProcessMemory_b429 {
  strings:
    $key_b429 = { e3 5b [2] d1 79 [2] d7 4c [2] f9 4c [2] c6 50 }

  condition:
    any of them
}