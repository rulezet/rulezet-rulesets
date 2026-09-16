rule TTP_XOR_WriteProcessMemory_83a3 {
  strings:
    $key_83a3 = { d4 d1 [2] e6 f3 [2] e0 c6 [2] ce c6 [2] f1 da }

  condition:
    any of them
}