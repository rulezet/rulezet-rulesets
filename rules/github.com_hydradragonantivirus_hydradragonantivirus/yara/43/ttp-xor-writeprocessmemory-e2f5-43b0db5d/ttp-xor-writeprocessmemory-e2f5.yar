rule TTP_XOR_WriteProcessMemory_e2f5 {
  strings:
    $key_e2f5 = { b5 87 [2] 87 a5 [2] 81 90 [2] af 90 [2] 90 8c }

  condition:
    any of them
}