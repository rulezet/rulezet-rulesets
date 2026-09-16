rule TTP_XOR_WriteProcessMemory_aa23 {
  strings:
    $key_aa23 = { fd 51 [2] cf 73 [2] c9 46 [2] e7 46 [2] d8 5a }

  condition:
    any of them
}