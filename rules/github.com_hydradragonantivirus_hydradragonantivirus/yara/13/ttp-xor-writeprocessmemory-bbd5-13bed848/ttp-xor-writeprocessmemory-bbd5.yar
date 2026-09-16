rule TTP_XOR_WriteProcessMemory_bbd5 {
  strings:
    $key_bbd5 = { ec a7 [2] de 85 [2] d8 b0 [2] f6 b0 [2] c9 ac }

  condition:
    any of them
}