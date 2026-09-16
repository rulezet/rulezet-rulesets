rule TTP_XOR_WriteProcessMemory_72c3 {
  strings:
    $key_72c3 = { 25 b1 [2] 17 93 [2] 11 a6 [2] 3f a6 [2] 00 ba }

  condition:
    any of them
}