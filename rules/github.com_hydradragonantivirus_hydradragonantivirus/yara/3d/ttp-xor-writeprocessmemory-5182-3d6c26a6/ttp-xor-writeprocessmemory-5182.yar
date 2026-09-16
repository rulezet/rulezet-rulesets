rule TTP_XOR_WriteProcessMemory_5182 {
  strings:
    $key_5182 = { 06 f0 [2] 34 d2 [2] 32 e7 [2] 1c e7 [2] 23 fb }

  condition:
    any of them
}