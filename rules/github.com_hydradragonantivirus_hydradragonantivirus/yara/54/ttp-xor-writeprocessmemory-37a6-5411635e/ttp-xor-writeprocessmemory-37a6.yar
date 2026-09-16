rule TTP_XOR_WriteProcessMemory_37a6 {
  strings:
    $key_37a6 = { 60 d4 [2] 52 f6 [2] 54 c3 [2] 7a c3 [2] 45 df }

  condition:
    any of them
}