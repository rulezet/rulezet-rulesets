rule TTP_XOR_WriteProcessMemory_6386 {
  strings:
    $key_6386 = { 34 f4 [2] 06 d6 [2] 00 e3 [2] 2e e3 [2] 11 ff }

  condition:
    any of them
}