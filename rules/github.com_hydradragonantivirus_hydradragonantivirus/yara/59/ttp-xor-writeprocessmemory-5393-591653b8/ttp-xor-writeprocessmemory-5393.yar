rule TTP_XOR_WriteProcessMemory_5393 {
  strings:
    $key_5393 = { 04 e1 [2] 36 c3 [2] 30 f6 [2] 1e f6 [2] 21 ea }

  condition:
    any of them
}