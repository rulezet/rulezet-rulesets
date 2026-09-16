rule TTP_XOR_WriteProcessMemory_bbc3 {
  strings:
    $key_bbc3 = { ec b1 [2] de 93 [2] d8 a6 [2] f6 a6 [2] c9 ba }

  condition:
    any of them
}