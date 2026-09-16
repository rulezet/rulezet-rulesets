rule TTP_XOR_WriteProcessMemory_06c0 {
  strings:
    $key_06c0 = { 51 b2 [2] 63 90 [2] 65 a5 [2] 4b a5 [2] 74 b9 }

  condition:
    any of them
}