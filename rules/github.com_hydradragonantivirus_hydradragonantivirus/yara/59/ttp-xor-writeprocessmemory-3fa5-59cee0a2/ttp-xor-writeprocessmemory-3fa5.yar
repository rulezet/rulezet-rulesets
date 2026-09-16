rule TTP_XOR_WriteProcessMemory_3fa5 {
  strings:
    $key_3fa5 = { 68 d7 [2] 5a f5 [2] 5c c0 [2] 72 c0 [2] 4d dc }

  condition:
    any of them
}