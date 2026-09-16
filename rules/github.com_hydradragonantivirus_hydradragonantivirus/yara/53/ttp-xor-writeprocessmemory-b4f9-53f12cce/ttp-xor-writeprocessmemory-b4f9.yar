rule TTP_XOR_WriteProcessMemory_b4f9 {
  strings:
    $key_b4f9 = { e3 8b [2] d1 a9 [2] d7 9c [2] f9 9c [2] c6 80 }

  condition:
    any of them
}