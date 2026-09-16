rule TTP_XOR_WriteProcessMemory_6bd9 {
  strings:
    $key_6bd9 = { 3c ab [2] 0e 89 [2] 08 bc [2] 26 bc [2] 19 a0 }

  condition:
    any of them
}