rule TTP_XOR_WriteProcessMemory_5bd9 {
  strings:
    $key_5bd9 = { 0c ab [2] 3e 89 [2] 38 bc [2] 16 bc [2] 29 a0 }

  condition:
    any of them
}