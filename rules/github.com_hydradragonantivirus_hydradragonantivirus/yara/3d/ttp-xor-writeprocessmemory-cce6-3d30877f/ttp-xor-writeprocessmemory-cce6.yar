rule TTP_XOR_WriteProcessMemory_cce6 {
  strings:
    $key_cce6 = { 9b 94 [2] a9 b6 [2] af 83 [2] 81 83 [2] be 9f }

  condition:
    any of them
}