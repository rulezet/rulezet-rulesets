rule TTP_XOR_WriteProcessMemory_e2e0 {
  strings:
    $key_e2e0 = { b5 92 [2] 87 b0 [2] 81 85 [2] af 85 [2] 90 99 }

  condition:
    any of them
}