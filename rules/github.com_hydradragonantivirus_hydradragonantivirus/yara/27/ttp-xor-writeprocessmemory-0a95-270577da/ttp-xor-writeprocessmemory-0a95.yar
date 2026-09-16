rule TTP_XOR_WriteProcessMemory_0a95 {
  strings:
    $key_0a95 = { 5d e7 [2] 6f c5 [2] 69 f0 [2] 47 f0 [2] 78 ec }

  condition:
    any of them
}