rule TTP_XOR_WriteProcessMemory_34c1 {
  strings:
    $key_34c1 = { 63 b3 [2] 51 91 [2] 57 a4 [2] 79 a4 [2] 46 b8 }

  condition:
    any of them
}