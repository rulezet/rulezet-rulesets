rule TTP_XOR_WriteProcessMemory_57b3 {
  strings:
    $key_57b3 = { 00 c1 [2] 32 e3 [2] 34 d6 [2] 1a d6 [2] 25 ca }

  condition:
    any of them
}