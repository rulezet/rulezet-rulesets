rule TTP_XOR_WriteProcessMemory_ec90 {
  strings:
    $key_ec90 = { bb e2 [2] 89 c0 [2] 8f f5 [2] a1 f5 [2] 9e e9 }

  condition:
    any of them
}