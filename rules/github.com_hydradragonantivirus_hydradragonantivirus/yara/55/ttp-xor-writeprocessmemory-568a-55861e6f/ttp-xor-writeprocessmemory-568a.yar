rule TTP_XOR_WriteProcessMemory_568a {
  strings:
    $key_568a = { 01 f8 [2] 33 da [2] 35 ef [2] 1b ef [2] 24 f3 }

  condition:
    any of them
}