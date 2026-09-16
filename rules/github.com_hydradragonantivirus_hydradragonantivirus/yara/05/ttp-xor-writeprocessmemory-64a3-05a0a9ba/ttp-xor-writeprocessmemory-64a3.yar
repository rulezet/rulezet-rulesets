rule TTP_XOR_WriteProcessMemory_64a3 {
  strings:
    $key_64a3 = { 33 d1 [2] 01 f3 [2] 07 c6 [2] 29 c6 [2] 16 da }

  condition:
    any of them
}