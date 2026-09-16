rule TTP_XOR_WriteProcessMemory_dd51 {
  strings:
    $key_dd51 = { 8a 23 [2] b8 01 [2] be 34 [2] 90 34 [2] af 28 }

  condition:
    any of them
}