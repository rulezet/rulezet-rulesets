rule TTP_XOR_WriteProcessMemory_b5b3 {
  strings:
    $key_b5b3 = { e2 c1 [2] d0 e3 [2] d6 d6 [2] f8 d6 [2] c7 ca }

  condition:
    any of them
}