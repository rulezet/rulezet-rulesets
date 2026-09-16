rule TTP_XOR_WriteProcessMemory_2095 {
  strings:
    $key_2095 = { 77 e7 [2] 45 c5 [2] 43 f0 [2] 6d f0 [2] 52 ec }

  condition:
    any of them
}