rule TTP_XOR_WriteProcessMemory_ddd4 {
  strings:
    $key_ddd4 = { 8a a6 [2] b8 84 [2] be b1 [2] 90 b1 [2] af ad }

  condition:
    any of them
}