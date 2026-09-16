rule TTP_XOR_WriteProcessMemory_aa03 {
  strings:
    $key_aa03 = { fd 71 [2] cf 53 [2] c9 66 [2] e7 66 [2] d8 7a }

  condition:
    any of them
}