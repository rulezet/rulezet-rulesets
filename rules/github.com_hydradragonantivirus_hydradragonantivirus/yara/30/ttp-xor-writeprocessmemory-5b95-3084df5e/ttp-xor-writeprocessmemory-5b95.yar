rule TTP_XOR_WriteProcessMemory_5b95 {
  strings:
    $key_5b95 = { 0c e7 [2] 3e c5 [2] 38 f0 [2] 16 f0 [2] 29 ec }

  condition:
    any of them
}