rule TTP_XOR_WriteProcessMemory_e2f3 {
  strings:
    $key_e2f3 = { b5 81 [2] 87 a3 [2] 81 96 [2] af 96 [2] 90 8a }

  condition:
    any of them
}