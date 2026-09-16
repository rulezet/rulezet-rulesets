rule TTP_XOR_WriteProcessMemory_7d36 {
  strings:
    $key_7d36 = { 2a 44 [2] 18 66 [2] 1e 53 [2] 30 53 [2] 0f 4f }

  condition:
    any of them
}