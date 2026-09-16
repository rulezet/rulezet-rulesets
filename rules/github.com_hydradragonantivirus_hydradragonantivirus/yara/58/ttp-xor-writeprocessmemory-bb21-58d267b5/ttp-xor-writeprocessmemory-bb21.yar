rule TTP_XOR_WriteProcessMemory_bb21 {
  strings:
    $key_bb21 = { ec 53 [2] de 71 [2] d8 44 [2] f6 44 [2] c9 58 }

  condition:
    any of them
}