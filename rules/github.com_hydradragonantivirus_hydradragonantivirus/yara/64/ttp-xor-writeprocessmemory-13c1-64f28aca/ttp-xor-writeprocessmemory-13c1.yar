rule TTP_XOR_WriteProcessMemory_13c1 {
  strings:
    $key_13c1 = { 44 b3 [2] 76 91 [2] 70 a4 [2] 5e a4 [2] 61 b8 }

  condition:
    any of them
}