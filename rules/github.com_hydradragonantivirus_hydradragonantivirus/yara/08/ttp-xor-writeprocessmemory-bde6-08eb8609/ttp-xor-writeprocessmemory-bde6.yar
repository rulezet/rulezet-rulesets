rule TTP_XOR_WriteProcessMemory_bde6 {
  strings:
    $key_bde6 = { ea 94 [2] d8 b6 [2] de 83 [2] f0 83 [2] cf 9f }

  condition:
    any of them
}