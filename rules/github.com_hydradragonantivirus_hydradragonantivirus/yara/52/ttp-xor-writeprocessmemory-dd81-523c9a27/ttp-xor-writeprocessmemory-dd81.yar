rule TTP_XOR_WriteProcessMemory_dd81 {
  strings:
    $key_dd81 = { 8a f3 [2] b8 d1 [2] be e4 [2] 90 e4 [2] af f8 }

  condition:
    any of them
}