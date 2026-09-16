rule TTP_XOR_WriteProcessMemory_aa60 {
  strings:
    $key_aa60 = { fd 12 [2] cf 30 [2] c9 05 [2] e7 05 [2] d8 19 }

  condition:
    any of them
}