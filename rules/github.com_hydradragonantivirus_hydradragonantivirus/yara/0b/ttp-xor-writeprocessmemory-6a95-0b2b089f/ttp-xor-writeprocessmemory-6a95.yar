rule TTP_XOR_WriteProcessMemory_6a95 {
  strings:
    $key_6a95 = { 3d e7 [2] 0f c5 [2] 09 f0 [2] 27 f0 [2] 18 ec }

  condition:
    any of them
}