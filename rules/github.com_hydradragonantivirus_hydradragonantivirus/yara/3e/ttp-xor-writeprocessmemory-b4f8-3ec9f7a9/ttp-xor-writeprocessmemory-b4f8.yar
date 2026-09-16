rule TTP_XOR_WriteProcessMemory_b4f8 {
  strings:
    $key_b4f8 = { e3 8a [2] d1 a8 [2] d7 9d [2] f9 9d [2] c6 81 }

  condition:
    any of them
}