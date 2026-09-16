rule TTP_XOR_WriteProcessMemory_0e95 {
  strings:
    $key_0e95 = { 59 e7 [2] 6b c5 [2] 6d f0 [2] 43 f0 [2] 7c ec }

  condition:
    any of them
}