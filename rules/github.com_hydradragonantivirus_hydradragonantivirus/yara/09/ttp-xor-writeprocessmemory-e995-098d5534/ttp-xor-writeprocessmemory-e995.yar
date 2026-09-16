rule TTP_XOR_WriteProcessMemory_e995 {
  strings:
    $key_e995 = { be e7 [2] 8c c5 [2] 8a f0 [2] a4 f0 [2] 9b ec }

  condition:
    any of them
}