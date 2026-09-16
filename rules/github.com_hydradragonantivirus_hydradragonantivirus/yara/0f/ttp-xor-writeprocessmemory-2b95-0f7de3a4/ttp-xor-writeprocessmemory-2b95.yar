rule TTP_XOR_WriteProcessMemory_2b95 {
  strings:
    $key_2b95 = { 7c e7 [2] 4e c5 [2] 48 f0 [2] 66 f0 [2] 59 ec }

  condition:
    any of them
}