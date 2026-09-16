rule TTP_XOR_WriteProcessMemory_e2c0 {
  strings:
    $key_e2c0 = { b5 b2 [2] 87 90 [2] 81 a5 [2] af a5 [2] 90 b9 }

  condition:
    any of them
}