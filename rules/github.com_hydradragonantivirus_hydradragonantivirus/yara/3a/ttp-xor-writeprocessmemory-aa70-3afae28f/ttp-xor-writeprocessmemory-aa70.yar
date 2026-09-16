rule TTP_XOR_WriteProcessMemory_aa70 {
  strings:
    $key_aa70 = { fd 02 [2] cf 20 [2] c9 15 [2] e7 15 [2] d8 09 }

  condition:
    any of them
}