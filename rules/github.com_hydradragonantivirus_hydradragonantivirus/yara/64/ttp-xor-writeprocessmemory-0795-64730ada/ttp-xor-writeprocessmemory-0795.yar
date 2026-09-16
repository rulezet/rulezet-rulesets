rule TTP_XOR_WriteProcessMemory_0795 {
  strings:
    $key_0795 = { 50 e7 [2] 62 c5 [2] 64 f0 [2] 4a f0 [2] 75 ec }

  condition:
    any of them
}