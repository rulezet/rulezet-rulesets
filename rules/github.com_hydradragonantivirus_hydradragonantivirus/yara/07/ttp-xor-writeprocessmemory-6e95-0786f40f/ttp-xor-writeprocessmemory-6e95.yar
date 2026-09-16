rule TTP_XOR_WriteProcessMemory_6e95 {
  strings:
    $key_6e95 = { 39 e7 [2] 0b c5 [2] 0d f0 [2] 23 f0 [2] 1c ec }

  condition:
    any of them
}