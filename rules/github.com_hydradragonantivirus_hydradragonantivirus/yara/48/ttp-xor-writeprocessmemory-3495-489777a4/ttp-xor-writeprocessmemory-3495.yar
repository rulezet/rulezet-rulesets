rule TTP_XOR_WriteProcessMemory_3495 {
  strings:
    $key_3495 = { 63 e7 [2] 51 c5 [2] 57 f0 [2] 79 f0 [2] 46 ec }

  condition:
    any of them
}