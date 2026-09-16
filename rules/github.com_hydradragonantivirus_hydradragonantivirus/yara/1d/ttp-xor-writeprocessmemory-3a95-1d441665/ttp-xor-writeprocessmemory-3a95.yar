rule TTP_XOR_WriteProcessMemory_3a95 {
  strings:
    $key_3a95 = { 6d e7 [2] 5f c5 [2] 59 f0 [2] 77 f0 [2] 48 ec }

  condition:
    any of them
}