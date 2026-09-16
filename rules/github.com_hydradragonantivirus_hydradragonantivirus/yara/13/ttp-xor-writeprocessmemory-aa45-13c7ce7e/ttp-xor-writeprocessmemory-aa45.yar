rule TTP_XOR_WriteProcessMemory_aa45 {
  strings:
    $key_aa45 = { fd 37 [2] cf 15 [2] c9 20 [2] e7 20 [2] d8 3c }

  condition:
    any of them
}