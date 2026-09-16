rule TTP_XOR_WriteProcessMemory_7095 {
  strings:
    $key_7095 = { 27 e7 [2] 15 c5 [2] 13 f0 [2] 3d f0 [2] 02 ec }

  condition:
    any of them
}