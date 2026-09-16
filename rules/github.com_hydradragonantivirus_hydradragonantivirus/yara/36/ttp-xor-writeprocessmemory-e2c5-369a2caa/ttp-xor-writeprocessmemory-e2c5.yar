rule TTP_XOR_WriteProcessMemory_e2c5 {
  strings:
    $key_e2c5 = { b5 b7 [2] 87 95 [2] 81 a0 [2] af a0 [2] 90 bc }

  condition:
    any of them
}