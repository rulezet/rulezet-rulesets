rule TTP_XOR_WriteProcessMemory_06a3 {
  strings:
    $key_06a3 = { 51 d1 [2] 63 f3 [2] 65 c6 [2] 4b c6 [2] 74 da }

  condition:
    any of them
}