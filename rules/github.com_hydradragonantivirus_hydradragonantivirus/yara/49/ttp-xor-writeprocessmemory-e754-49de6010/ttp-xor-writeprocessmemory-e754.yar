rule TTP_XOR_WriteProcessMemory_e754 {
  strings:
    $key_e754 = { b0 26 [2] 82 04 [2] 84 31 [2] aa 31 [2] 95 2d }

  condition:
    any of them
}