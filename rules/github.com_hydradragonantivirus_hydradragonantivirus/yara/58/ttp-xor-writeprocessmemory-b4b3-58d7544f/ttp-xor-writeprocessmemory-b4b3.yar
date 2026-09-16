rule TTP_XOR_WriteProcessMemory_b4b3 {
  strings:
    $key_b4b3 = { e3 c1 [2] d1 e3 [2] d7 d6 [2] f9 d6 [2] c6 ca }

  condition:
    any of them
}