rule TTP_XOR_WriteProcessMemory_ec91 {
  strings:
    $key_ec91 = { bb e3 [2] 89 c1 [2] 8f f4 [2] a1 f4 [2] 9e e8 }

  condition:
    any of them
}