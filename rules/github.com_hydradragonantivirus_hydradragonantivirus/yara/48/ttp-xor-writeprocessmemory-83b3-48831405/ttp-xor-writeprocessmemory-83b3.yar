rule TTP_XOR_WriteProcessMemory_83b3 {
  strings:
    $key_83b3 = { d4 c1 [2] e6 e3 [2] e0 d6 [2] ce d6 [2] f1 ca }

  condition:
    any of them
}