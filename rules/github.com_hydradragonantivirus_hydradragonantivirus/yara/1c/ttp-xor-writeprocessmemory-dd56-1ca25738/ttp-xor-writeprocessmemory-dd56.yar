rule TTP_XOR_WriteProcessMemory_dd56 {
  strings:
    $key_dd56 = { 8a 24 [2] b8 06 [2] be 33 [2] 90 33 [2] af 2f }

  condition:
    any of them
}