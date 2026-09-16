rule TTP_XOR_WriteProcessMemory_9f95 {
  strings:
    $key_9f95 = { c8 e7 [2] fa c5 [2] fc f0 [2] d2 f0 [2] ed ec }

  condition:
    any of them
}