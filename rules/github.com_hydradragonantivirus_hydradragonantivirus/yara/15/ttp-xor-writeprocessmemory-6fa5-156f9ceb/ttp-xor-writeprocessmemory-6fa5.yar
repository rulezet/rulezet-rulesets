rule TTP_XOR_WriteProcessMemory_6fa5 {
  strings:
    $key_6fa5 = { 38 d7 [2] 0a f5 [2] 0c c0 [2] 22 c0 [2] 1d dc }

  condition:
    any of them
}