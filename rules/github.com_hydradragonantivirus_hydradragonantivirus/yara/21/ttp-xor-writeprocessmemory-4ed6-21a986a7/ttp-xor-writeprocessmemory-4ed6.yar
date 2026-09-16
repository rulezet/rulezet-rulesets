rule TTP_XOR_WriteProcessMemory_4ed6 {
  strings:
    $key_4ed6 = { 19 a4 [2] 2b 86 [2] 2d b3 [2] 03 b3 [2] 3c af }

  condition:
    any of them
}