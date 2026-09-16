rule TTP_XOR_WriteProcessMemory_52d1 {
  strings:
    $key_52d1 = { 05 a3 [2] 37 81 [2] 31 b4 [2] 1f b4 [2] 20 a8 }

  condition:
    any of them
}