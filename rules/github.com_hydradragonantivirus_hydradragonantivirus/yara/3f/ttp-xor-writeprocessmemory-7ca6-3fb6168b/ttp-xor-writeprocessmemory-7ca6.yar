rule TTP_XOR_WriteProcessMemory_7ca6 {
  strings:
    $key_7ca6 = { 2b d4 [2] 19 f6 [2] 1f c3 [2] 31 c3 [2] 0e df }

  condition:
    any of them
}