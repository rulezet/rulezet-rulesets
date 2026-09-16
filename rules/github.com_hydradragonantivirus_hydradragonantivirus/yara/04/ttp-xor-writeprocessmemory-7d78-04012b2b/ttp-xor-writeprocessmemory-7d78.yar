rule TTP_XOR_WriteProcessMemory_7d78 {
  strings:
    $key_7d78 = { 2a 0a [2] 18 28 [2] 1e 1d [2] 30 1d [2] 0f 01 }

  condition:
    any of them
}