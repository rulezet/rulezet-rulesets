rule TTP_XOR_WriteProcessMemory_aa47 {
  strings:
    $key_aa47 = { fd 35 [2] cf 17 [2] c9 22 [2] e7 22 [2] d8 3e }

  condition:
    any of them
}