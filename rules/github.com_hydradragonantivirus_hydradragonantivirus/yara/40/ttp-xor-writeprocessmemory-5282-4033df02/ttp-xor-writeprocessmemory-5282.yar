rule TTP_XOR_WriteProcessMemory_5282 {
  strings:
    $key_5282 = { 05 f0 [2] 37 d2 [2] 31 e7 [2] 1f e7 [2] 20 fb }

  condition:
    any of them
}