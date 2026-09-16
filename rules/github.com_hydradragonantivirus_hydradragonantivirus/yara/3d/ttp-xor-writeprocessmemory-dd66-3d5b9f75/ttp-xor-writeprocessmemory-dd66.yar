rule TTP_XOR_WriteProcessMemory_dd66 {
  strings:
    $key_dd66 = { 8a 14 [2] b8 36 [2] be 03 [2] 90 03 [2] af 1f }

  condition:
    any of them
}