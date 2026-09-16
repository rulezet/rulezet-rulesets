rule TTP_XOR_WriteProcessMemory_aa27 {
  strings:
    $key_aa27 = { fd 55 [2] cf 77 [2] c9 42 [2] e7 42 [2] d8 5e }

  condition:
    any of them
}