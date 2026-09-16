rule TTP_XOR_WriteProcessMemory_b5f4 {
  strings:
    $key_b5f4 = { e2 86 [2] d0 a4 [2] d6 91 [2] f8 91 [2] c7 8d }

  condition:
    any of them
}