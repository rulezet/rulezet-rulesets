rule TTP_XOR_WriteProcessMemory_52d9 {
  strings:
    $key_52d9 = { 05 ab [2] 37 89 [2] 31 bc [2] 1f bc [2] 20 a0 }

  condition:
    any of them
}