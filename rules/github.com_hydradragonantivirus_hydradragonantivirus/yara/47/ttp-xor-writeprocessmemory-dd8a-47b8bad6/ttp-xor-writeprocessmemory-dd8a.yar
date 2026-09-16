rule TTP_XOR_WriteProcessMemory_dd8a {
  strings:
    $key_dd8a = { 8a f8 [2] b8 da [2] be ef [2] 90 ef [2] af f3 }

  condition:
    any of them
}