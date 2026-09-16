rule TTP_XOR_WriteProcessMemory_53b3 {
  strings:
    $key_53b3 = { 04 c1 [2] 36 e3 [2] 30 d6 [2] 1e d6 [2] 21 ca }

  condition:
    any of them
}