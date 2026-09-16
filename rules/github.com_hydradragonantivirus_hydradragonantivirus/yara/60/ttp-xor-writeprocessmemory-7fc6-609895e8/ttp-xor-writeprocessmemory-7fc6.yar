rule TTP_XOR_WriteProcessMemory_7fc6 {
  strings:
    $key_7fc6 = { 28 b4 [2] 1a 96 [2] 1c a3 [2] 32 a3 [2] 0d bf }

  condition:
    any of them
}