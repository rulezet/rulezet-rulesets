rule TTP_XOR_WriteProcessMemory_83a4 {
  strings:
    $key_83a4 = { d4 d6 [2] e6 f4 [2] e0 c1 [2] ce c1 [2] f1 dd }

  condition:
    any of them
}