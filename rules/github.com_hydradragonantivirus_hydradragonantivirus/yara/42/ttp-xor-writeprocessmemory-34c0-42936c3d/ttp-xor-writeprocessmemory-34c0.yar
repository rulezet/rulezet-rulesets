rule TTP_XOR_WriteProcessMemory_34c0 {
  strings:
    $key_34c0 = { 63 b2 [2] 51 90 [2] 57 a5 [2] 79 a5 [2] 46 b9 }

  condition:
    any of them
}