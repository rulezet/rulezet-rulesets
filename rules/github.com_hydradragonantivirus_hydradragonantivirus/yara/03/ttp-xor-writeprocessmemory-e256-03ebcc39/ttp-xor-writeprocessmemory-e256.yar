rule TTP_XOR_WriteProcessMemory_e256 {
  strings:
    $key_e256 = { b5 24 [2] 87 06 [2] 81 33 [2] af 33 [2] 90 2f }

  condition:
    any of them
}