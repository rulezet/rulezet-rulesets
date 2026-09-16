rule TTP_XOR_WriteProcessMemory_2d95 {
  strings:
    $key_2d95 = { 7a e7 [2] 48 c5 [2] 4e f0 [2] 60 f0 [2] 5f ec }

  condition:
    any of them
}