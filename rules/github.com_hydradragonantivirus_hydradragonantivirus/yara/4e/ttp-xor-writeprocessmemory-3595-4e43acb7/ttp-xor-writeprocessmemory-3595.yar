rule TTP_XOR_WriteProcessMemory_3595 {
  strings:
    $key_3595 = { 62 e7 [2] 50 c5 [2] 56 f0 [2] 78 f0 [2] 47 ec }

  condition:
    any of them
}