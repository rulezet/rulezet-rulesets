rule TTP_XOR_WriteProcessMemory_3fc0 {
  strings:
    $key_3fc0 = { 68 b2 [2] 5a 90 [2] 5c a5 [2] 72 a5 [2] 4d b9 }

  condition:
    any of them
}