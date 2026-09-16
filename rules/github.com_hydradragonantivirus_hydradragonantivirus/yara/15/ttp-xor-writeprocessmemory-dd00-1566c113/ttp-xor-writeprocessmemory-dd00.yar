rule TTP_XOR_WriteProcessMemory_dd00 {
  strings:
    $key_dd00 = { 8a 72 [2] b8 50 [2] be 65 [2] 90 65 [2] af 79 }

  condition:
    any of them
}