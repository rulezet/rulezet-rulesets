rule TTP_XOR_WriteProcessMemory_aa35 {
  strings:
    $key_aa35 = { fd 47 [2] cf 65 [2] c9 50 [2] e7 50 [2] d8 4c }

  condition:
    any of them
}