rule TTP_XOR_WriteProcessMemory_e736 {
  strings:
    $key_e736 = { b0 44 [2] 82 66 [2] 84 53 [2] aa 53 [2] 95 4f }

  condition:
    any of them
}