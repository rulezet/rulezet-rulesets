rule TTP_XOR_WriteProcessMemory_7f83 {
  strings:
    $key_7f83 = { 28 f1 [2] 1a d3 [2] 1c e6 [2] 32 e6 [2] 0d fa }

  condition:
    any of them
}