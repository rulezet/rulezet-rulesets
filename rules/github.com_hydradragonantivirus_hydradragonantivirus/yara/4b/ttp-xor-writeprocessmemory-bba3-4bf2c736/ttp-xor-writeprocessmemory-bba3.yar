rule TTP_XOR_WriteProcessMemory_bba3 {
  strings:
    $key_bba3 = { ec d1 [2] de f3 [2] d8 c6 [2] f6 c6 [2] c9 da }

  condition:
    any of them
}