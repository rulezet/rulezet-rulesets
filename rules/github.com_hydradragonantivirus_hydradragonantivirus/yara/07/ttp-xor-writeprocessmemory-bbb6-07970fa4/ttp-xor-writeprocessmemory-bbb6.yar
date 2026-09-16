rule TTP_XOR_WriteProcessMemory_bbb6 {
  strings:
    $key_bbb6 = { ec c4 [2] de e6 [2] d8 d3 [2] f6 d3 [2] c9 cf }

  condition:
    any of them
}