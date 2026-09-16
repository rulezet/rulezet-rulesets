rule TTP_XOR_WriteProcessMemory_bb83 {
  strings:
    $key_bb83 = { ec f1 [2] de d3 [2] d8 e6 [2] f6 e6 [2] c9 fa }

  condition:
    any of them
}