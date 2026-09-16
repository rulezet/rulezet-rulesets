rule TTP_XOR_WriteProcessMemory_bbb0 {
  strings:
    $key_bbb0 = { ec c2 [2] de e0 [2] d8 d5 [2] f6 d5 [2] c9 c9 }

  condition:
    any of them
}