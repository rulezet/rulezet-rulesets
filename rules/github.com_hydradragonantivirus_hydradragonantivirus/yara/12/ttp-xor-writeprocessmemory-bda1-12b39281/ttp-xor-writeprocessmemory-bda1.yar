rule TTP_XOR_WriteProcessMemory_bda1 {
  strings:
    $key_bda1 = { ea d3 [2] d8 f1 [2] de c4 [2] f0 c4 [2] cf d8 }

  condition:
    any of them
}