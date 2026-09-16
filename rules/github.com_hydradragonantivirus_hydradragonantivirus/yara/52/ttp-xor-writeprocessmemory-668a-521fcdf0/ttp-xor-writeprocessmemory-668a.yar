rule TTP_XOR_WriteProcessMemory_668a {
  strings:
    $key_668a = { 31 f8 [2] 03 da [2] 05 ef [2] 2b ef [2] 14 f3 }

  condition:
    any of them
}