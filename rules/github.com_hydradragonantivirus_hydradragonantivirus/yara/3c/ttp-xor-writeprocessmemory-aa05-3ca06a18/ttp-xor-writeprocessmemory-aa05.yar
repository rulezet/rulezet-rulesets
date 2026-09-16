rule TTP_XOR_WriteProcessMemory_aa05 {
  strings:
    $key_aa05 = { fd 77 [2] cf 55 [2] c9 60 [2] e7 60 [2] d8 7c }

  condition:
    any of them
}