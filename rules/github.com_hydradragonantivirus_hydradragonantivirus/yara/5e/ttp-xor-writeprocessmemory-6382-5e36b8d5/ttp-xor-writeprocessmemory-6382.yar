rule TTP_XOR_WriteProcessMemory_6382 {
  strings:
    $key_6382 = { 34 f0 [2] 06 d2 [2] 00 e7 [2] 2e e7 [2] 11 fb }

  condition:
    any of them
}