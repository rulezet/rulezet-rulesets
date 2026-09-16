rule TTP_XOR_WriteProcessMemory_7d63 {
  strings:
    $key_7d63 = { 2a 11 [2] 18 33 [2] 1e 06 [2] 30 06 [2] 0f 1a }

  condition:
    any of them
}