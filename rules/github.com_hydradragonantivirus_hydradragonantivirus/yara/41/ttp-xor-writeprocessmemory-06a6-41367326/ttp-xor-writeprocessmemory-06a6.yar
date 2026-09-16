rule TTP_XOR_WriteProcessMemory_06a6 {
  strings:
    $key_06a6 = { 51 d4 [2] 63 f6 [2] 65 c3 [2] 4b c3 [2] 74 df }

  condition:
    any of them
}