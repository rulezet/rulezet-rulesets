rule TTP_XOR_WriteProcessMemory_0f83 {
  strings:
    $key_0f83 = { 58 f1 [2] 6a d3 [2] 6c e6 [2] 42 e6 [2] 7d fa }

  condition:
    any of them
}