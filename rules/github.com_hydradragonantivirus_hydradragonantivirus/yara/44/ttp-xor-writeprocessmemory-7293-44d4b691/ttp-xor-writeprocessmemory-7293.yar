rule TTP_XOR_WriteProcessMemory_7293 {
  strings:
    $key_7293 = { 25 e1 [2] 17 c3 [2] 11 f6 [2] 3f f6 [2] 00 ea }

  condition:
    any of them
}