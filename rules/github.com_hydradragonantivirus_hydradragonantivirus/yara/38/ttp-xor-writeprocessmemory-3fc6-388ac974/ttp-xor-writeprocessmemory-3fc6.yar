rule TTP_XOR_WriteProcessMemory_3fc6 {
  strings:
    $key_3fc6 = { 68 b4 [2] 5a 96 [2] 5c a3 [2] 72 a3 [2] 4d bf }

  condition:
    any of them
}