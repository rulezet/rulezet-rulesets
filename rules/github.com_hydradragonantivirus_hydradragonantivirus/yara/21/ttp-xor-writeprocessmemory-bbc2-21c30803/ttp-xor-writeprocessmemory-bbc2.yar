rule TTP_XOR_WriteProcessMemory_bbc2 {
  strings:
    $key_bbc2 = { ec b0 [2] de 92 [2] d8 a7 [2] f6 a7 [2] c9 bb }

  condition:
    any of them
}