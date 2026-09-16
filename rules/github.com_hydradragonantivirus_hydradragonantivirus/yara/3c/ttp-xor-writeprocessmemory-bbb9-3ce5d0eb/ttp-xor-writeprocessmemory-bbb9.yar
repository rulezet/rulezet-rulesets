rule TTP_XOR_WriteProcessMemory_bbb9 {
  strings:
    $key_bbb9 = { ec cb [2] de e9 [2] d8 dc [2] f6 dc [2] c9 c0 }

  condition:
    any of them
}