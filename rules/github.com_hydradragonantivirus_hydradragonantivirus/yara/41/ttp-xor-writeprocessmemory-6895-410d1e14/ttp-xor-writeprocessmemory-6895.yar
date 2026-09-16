rule TTP_XOR_WriteProcessMemory_6895 {
  strings:
    $key_6895 = { 3f e7 [2] 0d c5 [2] 0b f0 [2] 25 f0 [2] 1a ec }

  condition:
    any of them
}