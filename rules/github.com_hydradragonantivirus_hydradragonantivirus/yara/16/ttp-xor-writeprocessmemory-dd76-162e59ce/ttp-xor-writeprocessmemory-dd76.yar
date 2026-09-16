rule TTP_XOR_WriteProcessMemory_dd76 {
  strings:
    $key_dd76 = { 8a 04 [2] b8 26 [2] be 13 [2] 90 13 [2] af 0f }

  condition:
    any of them
}