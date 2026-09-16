rule TTP_XOR_WriteProcessMemory_7d24 {
  strings:
    $key_7d24 = { 2a 56 [2] 18 74 [2] 1e 41 [2] 30 41 [2] 0f 5d }

  condition:
    any of them
}