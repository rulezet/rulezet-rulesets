rule TTP_XOR_WriteProcessMemory_17a6 {
  strings:
    $key_17a6 = { 40 d4 [2] 72 f6 [2] 74 c3 [2] 5a c3 [2] 65 df }

  condition:
    any of them
}