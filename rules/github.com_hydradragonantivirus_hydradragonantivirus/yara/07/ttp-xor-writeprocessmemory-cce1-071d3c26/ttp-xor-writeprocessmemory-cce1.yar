rule TTP_XOR_WriteProcessMemory_cce1 {
  strings:
    $key_cce1 = { 9b 93 [2] a9 b1 [2] af 84 [2] 81 84 [2] be 98 }

  condition:
    any of them
}