rule TTP_XOR_WriteProcessMemory_aa07 {
  strings:
    $key_aa07 = { fd 75 [2] cf 57 [2] c9 62 [2] e7 62 [2] d8 7e }

  condition:
    any of them
}