rule TTP_XOR_WriteProcessMemory_7d31 {
  strings:
    $key_7d31 = { 2a 43 [2] 18 61 [2] 1e 54 [2] 30 54 [2] 0f 48 }

  condition:
    any of them
}