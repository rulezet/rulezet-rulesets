rule TTP_XOR_WriteProcessMemory_aa73 {
  strings:
    $key_aa73 = { fd 01 [2] cf 23 [2] c9 16 [2] e7 16 [2] d8 0a }

  condition:
    any of them
}