rule TTP_XOR_WriteProcessMemory_e076 {
  strings:
    $key_e076 = { b7 04 [2] 85 26 [2] 83 13 [2] ad 13 [2] 92 0f }

  condition:
    any of them
}