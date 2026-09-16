rule TTP_XOR_WriteProcessMemory_ec95 {
  strings:
    $key_ec95 = { bb e7 [2] 89 c5 [2] 8f f0 [2] a1 f0 [2] 9e ec }

  condition:
    any of them
}