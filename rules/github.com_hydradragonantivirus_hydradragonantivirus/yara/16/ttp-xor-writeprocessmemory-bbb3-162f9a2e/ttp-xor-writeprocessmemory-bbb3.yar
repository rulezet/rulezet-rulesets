rule TTP_XOR_WriteProcessMemory_bbb3 {
  strings:
    $key_bbb3 = { ec c1 [2] de e3 [2] d8 d6 [2] f6 d6 [2] c9 ca }

  condition:
    any of them
}