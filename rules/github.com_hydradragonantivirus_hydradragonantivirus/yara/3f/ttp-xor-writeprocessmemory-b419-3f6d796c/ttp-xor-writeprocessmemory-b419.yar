rule TTP_XOR_WriteProcessMemory_b419 {
  strings:
    $key_b419 = { e3 6b [2] d1 49 [2] d7 7c [2] f9 7c [2] c6 60 }

  condition:
    any of them
}