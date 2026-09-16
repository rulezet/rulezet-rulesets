rule TTP_XOR_WriteProcessMemory_bb81 {
  strings:
    $key_bb81 = { ec f3 [2] de d1 [2] d8 e4 [2] f6 e4 [2] c9 f8 }

  condition:
    any of them
}