rule TTP_XOR_WriteProcessMemory_ccc8 {
  strings:
    $key_ccc8 = { 9b ba [2] a9 98 [2] af ad [2] 81 ad [2] be b1 }

  condition:
    any of them
}