rule TTP_XOR_WriteProcessMemory_368a {
  strings:
    $key_368a = { 61 f8 [2] 53 da [2] 55 ef [2] 7b ef [2] 44 f3 }

  condition:
    any of them
}