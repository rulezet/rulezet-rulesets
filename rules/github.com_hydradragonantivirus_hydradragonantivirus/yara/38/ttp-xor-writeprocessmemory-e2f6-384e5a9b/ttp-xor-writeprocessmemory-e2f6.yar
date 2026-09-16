rule TTP_XOR_WriteProcessMemory_e2f6 {
  strings:
    $key_e2f6 = { b5 84 [2] 87 a6 [2] 81 93 [2] af 93 [2] 90 8f }

  condition:
    any of them
}