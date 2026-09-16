rule TTP_XOR_WriteProcessMemory_95e9 {
  strings:
    $key_95e9 = { c2 9b [2] f0 b9 [2] f6 8c [2] d8 8c [2] e7 90 }

  condition:
    any of them
}