rule TTP_XOR_WriteProcessMemory_0bd9 {
  strings:
    $key_0bd9 = { 5c ab [2] 6e 89 [2] 68 bc [2] 46 bc [2] 79 a0 }

  condition:
    any of them
}