rule TTP_XOR_WriteProcessMemory_7793 {
  strings:
    $key_7793 = { 20 e1 [2] 12 c3 [2] 14 f6 [2] 3a f6 [2] 05 ea }

  condition:
    any of them
}