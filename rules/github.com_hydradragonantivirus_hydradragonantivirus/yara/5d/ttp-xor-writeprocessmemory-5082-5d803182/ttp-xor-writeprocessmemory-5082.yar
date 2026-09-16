rule TTP_XOR_WriteProcessMemory_5082 {
  strings:
    $key_5082 = { 07 f0 [2] 35 d2 [2] 33 e7 [2] 1d e7 [2] 22 fb }

  condition:
    any of them
}