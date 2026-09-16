rule TTP_XOR_WriteProcessMemory_e2f7 {
  strings:
    $key_e2f7 = { b5 85 [2] 87 a7 [2] 81 92 [2] af 92 [2] 90 8e }

  condition:
    any of them
}