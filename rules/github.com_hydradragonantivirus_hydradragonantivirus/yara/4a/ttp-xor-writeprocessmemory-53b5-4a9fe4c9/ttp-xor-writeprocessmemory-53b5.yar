rule TTP_XOR_WriteProcessMemory_53b5 {
  strings:
    $key_53b5 = { 04 c7 [2] 36 e5 [2] 30 d0 [2] 1e d0 [2] 21 cc }

  condition:
    any of them
}