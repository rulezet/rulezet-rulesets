rule TTP_XOR_WriteProcessMemory_768a {
  strings:
    $key_768a = { 21 f8 [2] 13 da [2] 15 ef [2] 3b ef [2] 04 f3 }

  condition:
    any of them
}