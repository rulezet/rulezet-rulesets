rule TTP_XOR_WriteProcessMemory_3b95 {
  strings:
    $key_3b95 = { 6c e7 [2] 5e c5 [2] 58 f0 [2] 76 f0 [2] 49 ec }

  condition:
    any of them
}