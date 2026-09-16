rule TTP_XOR_WriteProcessMemory_62a6 {
  strings:
    $key_62a6 = { 35 d4 [2] 07 f6 [2] 01 c3 [2] 2f c3 [2] 10 df }

  condition:
    any of them
}