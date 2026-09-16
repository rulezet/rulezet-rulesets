rule TTP_XOR_WriteProcessMemory_7d18 {
  strings:
    $key_7d18 = { 2a 6a [2] 18 48 [2] 1e 7d [2] 30 7d [2] 0f 61 }

  condition:
    any of them
}