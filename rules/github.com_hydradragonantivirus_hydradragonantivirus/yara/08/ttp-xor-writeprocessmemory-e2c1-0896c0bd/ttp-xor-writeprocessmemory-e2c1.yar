rule TTP_XOR_WriteProcessMemory_e2c1 {
  strings:
    $key_e2c1 = { b5 b3 [2] 87 91 [2] 81 a4 [2] af a4 [2] 90 b8 }

  condition:
    any of them
}