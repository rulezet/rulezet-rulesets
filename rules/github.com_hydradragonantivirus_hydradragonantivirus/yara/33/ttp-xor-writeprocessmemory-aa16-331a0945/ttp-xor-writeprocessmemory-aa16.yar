rule TTP_XOR_WriteProcessMemory_aa16 {
  strings:
    $key_aa16 = { fd 64 [2] cf 46 [2] c9 73 [2] e7 73 [2] d8 6f }

  condition:
    any of them
}