rule TTP_XOR_WriteProcessMemory_52f0 {
  strings:
    $key_52f0 = { 05 82 [2] 37 a0 [2] 31 95 [2] 1f 95 [2] 20 89 }

  condition:
    any of them
}