rule TTP_XOR_WriteProcessMemory_e2d0 {
  strings:
    $key_e2d0 = { b5 a2 [2] 87 80 [2] 81 b5 [2] af b5 [2] 90 a9 }

  condition:
    any of them
}