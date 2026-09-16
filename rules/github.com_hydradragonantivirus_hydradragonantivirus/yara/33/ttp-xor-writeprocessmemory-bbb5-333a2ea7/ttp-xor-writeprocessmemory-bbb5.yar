rule TTP_XOR_WriteProcessMemory_bbb5 {
  strings:
    $key_bbb5 = { ec c7 [2] de e5 [2] d8 d0 [2] f6 d0 [2] c9 cc }

  condition:
    any of them
}