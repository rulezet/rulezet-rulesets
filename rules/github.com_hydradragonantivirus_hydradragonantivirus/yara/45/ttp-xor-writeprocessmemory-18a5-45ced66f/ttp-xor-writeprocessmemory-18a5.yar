rule TTP_XOR_WriteProcessMemory_18a5 {
  strings:
    $key_18a5 = { 4f d7 [2] 7d f5 [2] 7b c0 [2] 55 c0 [2] 6a dc }

  condition:
    any of them
}