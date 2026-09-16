rule TTP_XOR_WriteProcessMemory_7fc0 {
  strings:
    $key_7fc0 = { 28 b2 [2] 1a 90 [2] 1c a5 [2] 32 a5 [2] 0d b9 }

  condition:
    any of them
}