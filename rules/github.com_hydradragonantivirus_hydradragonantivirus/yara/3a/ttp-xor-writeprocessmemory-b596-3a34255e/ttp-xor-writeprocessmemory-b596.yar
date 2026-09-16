rule TTP_XOR_WriteProcessMemory_b596 {
  strings:
    $key_b596 = { e2 e4 [2] d0 c6 [2] d6 f3 [2] f8 f3 [2] c7 ef }

  condition:
    any of them
}