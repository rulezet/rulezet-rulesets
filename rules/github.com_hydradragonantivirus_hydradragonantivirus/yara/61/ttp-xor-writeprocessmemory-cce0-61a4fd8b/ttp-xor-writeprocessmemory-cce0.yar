rule TTP_XOR_WriteProcessMemory_cce0 {
  strings:
    $key_cce0 = { 9b 92 [2] a9 b0 [2] af 85 [2] 81 85 [2] be 99 }

  condition:
    any of them
}