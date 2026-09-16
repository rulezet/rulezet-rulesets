rule TTP_XOR_WriteProcessMemory_5370 {
  strings:
    $key_5370 = { 04 02 [2] 36 20 [2] 30 15 [2] 1e 15 [2] 21 09 }

  condition:
    any of them
}