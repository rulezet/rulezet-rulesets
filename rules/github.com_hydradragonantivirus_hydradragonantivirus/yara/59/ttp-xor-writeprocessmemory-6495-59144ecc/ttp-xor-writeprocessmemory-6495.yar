rule TTP_XOR_WriteProcessMemory_6495 {
  strings:
    $key_6495 = { 33 e7 [2] 01 c5 [2] 07 f0 [2] 29 f0 [2] 16 ec }

  condition:
    any of them
}