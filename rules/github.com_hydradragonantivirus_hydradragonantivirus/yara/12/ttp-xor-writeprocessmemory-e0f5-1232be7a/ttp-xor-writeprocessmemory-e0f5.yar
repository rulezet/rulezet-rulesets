rule TTP_XOR_WriteProcessMemory_e0f5 {
  strings:
    $key_e0f5 = { b7 87 [2] 85 a5 [2] 83 90 [2] ad 90 [2] 92 8c }

  condition:
    any of them
}