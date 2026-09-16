rule TTP_XOR_WriteProcessMemory_dd63 {
  strings:
    $key_dd63 = { 8a 11 [2] b8 33 [2] be 06 [2] 90 06 [2] af 1a }

  condition:
    any of them
}