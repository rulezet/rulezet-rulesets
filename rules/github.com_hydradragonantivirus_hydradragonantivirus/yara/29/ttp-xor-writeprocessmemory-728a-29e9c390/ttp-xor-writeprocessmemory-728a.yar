rule TTP_XOR_WriteProcessMemory_728a {
  strings:
    $key_728a = { 25 f8 [2] 17 da [2] 11 ef [2] 3f ef [2] 00 f3 }

  condition:
    any of them
}