rule TTP_XOR_WriteProcessMemory_aa71 {
  strings:
    $key_aa71 = { fd 03 [2] cf 21 [2] c9 14 [2] e7 14 [2] d8 08 }

  condition:
    any of them
}