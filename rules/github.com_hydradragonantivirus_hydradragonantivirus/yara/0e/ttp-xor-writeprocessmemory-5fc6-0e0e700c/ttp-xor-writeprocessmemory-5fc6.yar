rule TTP_XOR_WriteProcessMemory_5fc6 {
  strings:
    $key_5fc6 = { 08 b4 [2] 3a 96 [2] 3c a3 [2] 12 a3 [2] 2d bf }

  condition:
    any of them
}