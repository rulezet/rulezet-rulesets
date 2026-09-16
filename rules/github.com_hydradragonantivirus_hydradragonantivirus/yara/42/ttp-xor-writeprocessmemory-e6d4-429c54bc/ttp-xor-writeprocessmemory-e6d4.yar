rule TTP_XOR_WriteProcessMemory_e6d4 {
  strings:
    $key_e6d4 = { b1 a6 [2] 83 84 [2] 85 b1 [2] ab b1 [2] 94 ad }

  condition:
    any of them
}