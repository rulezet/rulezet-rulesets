rule TTP_XOR_WriteProcessMemory_ab46 {
  strings:
    $key_ab46 = { fc 34 [2] ce 16 [2] c8 23 [2] e6 23 [2] d9 3f }

  condition:
    any of them
}