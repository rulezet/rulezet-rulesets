rule TTP_XOR_WriteProcessMemory_5793 {
  strings:
    $key_5793 = { 00 e1 [2] 32 c3 [2] 34 f6 [2] 1a f6 [2] 25 ea }

  condition:
    any of them
}