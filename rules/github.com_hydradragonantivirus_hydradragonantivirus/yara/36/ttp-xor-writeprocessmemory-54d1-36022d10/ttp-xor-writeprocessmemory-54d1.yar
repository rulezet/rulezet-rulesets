rule TTP_XOR_WriteProcessMemory_54d1 {
  strings:
    $key_54d1 = { 03 a3 [2] 31 81 [2] 37 b4 [2] 19 b4 [2] 26 a8 }

  condition:
    any of them
}