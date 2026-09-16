rule TTP_XOR_WriteProcessMemory_5d95 {
  strings:
    $key_5d95 = { 0a e7 [2] 38 c5 [2] 3e f0 [2] 10 f0 [2] 2f ec }

  condition:
    any of them
}