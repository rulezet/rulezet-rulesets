rule TTP_XOR_WriteProcessMemory_aa75 {
  strings:
    $key_aa75 = { fd 07 [2] cf 25 [2] c9 10 [2] e7 10 [2] d8 0c }

  condition:
    any of them
}