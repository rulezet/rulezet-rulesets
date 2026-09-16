rule TTP_XOR_WriteProcessMemory_118a {
  strings:
    $key_118a = { 46 f8 [2] 74 da [2] 72 ef [2] 5c ef [2] 63 f3 }

  condition:
    any of them
}