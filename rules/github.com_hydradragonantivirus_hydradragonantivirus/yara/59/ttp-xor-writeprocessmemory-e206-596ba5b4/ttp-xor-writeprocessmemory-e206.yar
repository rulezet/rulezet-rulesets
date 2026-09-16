rule TTP_XOR_WriteProcessMemory_e206 {
  strings:
    $key_e206 = { b5 74 [2] 87 56 [2] 81 63 [2] af 63 [2] 90 7f }

  condition:
    any of them
}