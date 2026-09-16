rule TTP_XOR_WriteProcessMemory_7da9 {
  strings:
    $key_7da9 = { 2a db [2] 18 f9 [2] 1e cc [2] 30 cc [2] 0f d0 }

  condition:
    any of them
}