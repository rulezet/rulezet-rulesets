rule TTP_XOR_WriteProcessMemory_e6e6 {
  strings:
    $key_e6e6 = { b1 94 [2] 83 b6 [2] 85 83 [2] ab 83 [2] 94 9f }

  condition:
    any of them
}