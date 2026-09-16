rule TTP_XOR_WriteProcessMemory_7d04 {
  strings:
    $key_7d04 = { 2a 76 [2] 18 54 [2] 1e 61 [2] 30 61 [2] 0f 7d }

  condition:
    any of them
}