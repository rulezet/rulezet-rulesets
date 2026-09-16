rule TTP_XOR_WriteProcessMemory_8332 {
  strings:
    $key_8332 = { d4 40 [2] e6 62 [2] e0 57 [2] ce 57 [2] f1 4b }

  condition:
    any of them
}