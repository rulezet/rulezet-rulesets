rule TTP_XOR_WriteProcessMemory_b4a2 {
  strings:
    $key_b4a2 = { e3 d0 [2] d1 f2 [2] d7 c7 [2] f9 c7 [2] c6 db }

  condition:
    any of them
}