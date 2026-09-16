rule TTP_XOR_WriteProcessMemory_7393 {
  strings:
    $key_7393 = { 24 e1 [2] 16 c3 [2] 10 f6 [2] 3e f6 [2] 01 ea }

  condition:
    any of them
}