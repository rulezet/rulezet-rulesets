rule TTP_XOR_WriteProcessMemory_bbb1 {
  strings:
    $key_bbb1 = { ec c3 [2] de e1 [2] d8 d4 [2] f6 d4 [2] c9 c8 }

  condition:
    any of them
}