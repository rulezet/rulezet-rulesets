rule TTP_XOR_WriteProcessMemory_aa20 {
  strings:
    $key_aa20 = { fd 52 [2] cf 70 [2] c9 45 [2] e7 45 [2] d8 59 }

  condition:
    any of them
}