rule TTP_XOR_WriteProcessMemory_a5a2 {
  strings:
    $key_a5a2 = { f2 d0 [2] c0 f2 [2] c6 c7 [2] e8 c7 [2] d7 db }

  condition:
    any of them
}