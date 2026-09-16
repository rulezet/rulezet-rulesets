rule TTP_XOR_WriteProcessMemory_bde1 {
  strings:
    $key_bde1 = { ea 93 [2] d8 b1 [2] de 84 [2] f0 84 [2] cf 98 }

  condition:
    any of them
}