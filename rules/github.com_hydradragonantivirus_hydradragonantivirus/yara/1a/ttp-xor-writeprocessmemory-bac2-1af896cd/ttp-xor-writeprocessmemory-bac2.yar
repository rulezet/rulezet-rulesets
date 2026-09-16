rule TTP_XOR_WriteProcessMemory_bac2 {
  strings:
    $key_bac2 = { ed b0 [2] df 92 [2] d9 a7 [2] f7 a7 [2] c8 bb }

  condition:
    any of them
}