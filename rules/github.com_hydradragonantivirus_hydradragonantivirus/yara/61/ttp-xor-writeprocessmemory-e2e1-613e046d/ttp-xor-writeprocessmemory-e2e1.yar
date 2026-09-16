rule TTP_XOR_WriteProcessMemory_e2e1 {
  strings:
    $key_e2e1 = { b5 93 [2] 87 b1 [2] 81 84 [2] af 84 [2] 90 98 }

  condition:
    any of them
}