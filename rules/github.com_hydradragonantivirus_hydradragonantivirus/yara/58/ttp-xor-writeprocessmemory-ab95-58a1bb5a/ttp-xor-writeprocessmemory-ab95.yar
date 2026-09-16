rule TTP_XOR_WriteProcessMemory_ab95 {
  strings:
    $key_ab95 = { fc e7 [2] ce c5 [2] c8 f0 [2] e6 f0 [2] d9 ec }

  condition:
    any of them
}