rule TTP_XOR_WriteProcessMemory_72d9 {
  strings:
    $key_72d9 = { 25 ab [2] 17 89 [2] 11 bc [2] 3f bc [2] 00 a0 }

  condition:
    any of them
}