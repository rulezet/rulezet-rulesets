rule TTP_XOR_WriteProcessMemory_b5e3 {
  strings:
    $key_b5e3 = { e2 91 [2] d0 b3 [2] d6 86 [2] f8 86 [2] c7 9a }

  condition:
    any of them
}