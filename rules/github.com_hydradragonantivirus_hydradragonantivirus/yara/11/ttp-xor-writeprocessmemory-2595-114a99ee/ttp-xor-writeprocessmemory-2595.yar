rule TTP_XOR_WriteProcessMemory_2595 {
  strings:
    $key_2595 = { 72 e7 [2] 40 c5 [2] 46 f0 [2] 68 f0 [2] 57 ec }

  condition:
    any of them
}