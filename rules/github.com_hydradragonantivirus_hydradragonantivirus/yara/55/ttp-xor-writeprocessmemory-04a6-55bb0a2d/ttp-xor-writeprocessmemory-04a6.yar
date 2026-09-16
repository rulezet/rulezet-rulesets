rule TTP_XOR_WriteProcessMemory_04a6 {
  strings:
    $key_04a6 = { 53 d4 [2] 61 f6 [2] 67 c3 [2] 49 c3 [2] 76 df }

  condition:
    any of them
}