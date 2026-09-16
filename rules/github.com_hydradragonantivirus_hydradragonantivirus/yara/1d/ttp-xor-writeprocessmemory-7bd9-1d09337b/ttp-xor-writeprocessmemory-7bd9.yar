rule TTP_XOR_WriteProcessMemory_7bd9 {
  strings:
    $key_7bd9 = { 2c ab [2] 1e 89 [2] 18 bc [2] 36 bc [2] 09 a0 }

  condition:
    any of them
}