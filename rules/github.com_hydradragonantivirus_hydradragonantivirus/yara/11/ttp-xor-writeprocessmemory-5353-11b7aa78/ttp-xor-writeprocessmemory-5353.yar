rule TTP_XOR_WriteProcessMemory_5353 {
  strings:
    $key_5353 = { 04 21 [2] 36 03 [2] 30 36 [2] 1e 36 [2] 21 2a }

  condition:
    any of them
}