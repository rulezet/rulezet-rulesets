rule TTP_XOR_WriteProcessMemory_5482 {
  strings:
    $key_5482 = { 03 f0 [2] 31 d2 [2] 37 e7 [2] 19 e7 [2] 26 fb }

  condition:
    any of them
}