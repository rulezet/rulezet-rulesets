rule TTP_XOR_WriteProcessMemory_b4e3 {
  strings:
    $key_b4e3 = { e3 91 [2] d1 b3 [2] d7 86 [2] f9 86 [2] c6 9a }

  condition:
    any of them
}