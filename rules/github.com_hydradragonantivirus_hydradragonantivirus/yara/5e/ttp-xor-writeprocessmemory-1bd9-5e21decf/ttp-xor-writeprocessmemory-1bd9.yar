rule TTP_XOR_WriteProcessMemory_1bd9 {
  strings:
    $key_1bd9 = { 4c ab [2] 7e 89 [2] 78 bc [2] 56 bc [2] 69 a0 }

  condition:
    any of them
}