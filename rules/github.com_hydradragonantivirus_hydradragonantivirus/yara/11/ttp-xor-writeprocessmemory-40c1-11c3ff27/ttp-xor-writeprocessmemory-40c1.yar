rule TTP_XOR_WriteProcessMemory_40c1 {
  strings:
    $key_40c1 = { 17 b3 [2] 25 91 [2] 23 a4 [2] 0d a4 [2] 32 b8 }

  condition:
    any of them
}