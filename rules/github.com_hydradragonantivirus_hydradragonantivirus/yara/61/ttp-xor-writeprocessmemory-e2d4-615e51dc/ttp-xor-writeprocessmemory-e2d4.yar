rule TTP_XOR_WriteProcessMemory_e2d4 {
  strings:
    $key_e2d4 = { b5 a6 [2] 87 84 [2] 81 b1 [2] af b1 [2] 90 ad }

  condition:
    any of them
}