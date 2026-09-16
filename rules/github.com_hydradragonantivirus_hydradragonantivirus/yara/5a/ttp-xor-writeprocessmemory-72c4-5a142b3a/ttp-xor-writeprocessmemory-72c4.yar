rule TTP_XOR_WriteProcessMemory_72c4 {
  strings:
    $key_72c4 = { 25 b6 [2] 17 94 [2] 11 a1 [2] 3f a1 [2] 00 bd }

  condition:
    any of them
}