rule TTP_XOR_WriteProcessMemory_6095 {
  strings:
    $key_6095 = { 37 e7 [2] 05 c5 [2] 03 f0 [2] 2d f0 [2] 12 ec }

  condition:
    any of them
}