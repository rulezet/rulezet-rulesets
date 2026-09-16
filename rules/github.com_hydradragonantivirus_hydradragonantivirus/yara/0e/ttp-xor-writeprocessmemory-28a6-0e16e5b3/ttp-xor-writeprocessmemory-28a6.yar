rule TTP_XOR_WriteProcessMemory_28a6 {
  strings:
    $key_28a6 = { 7f d4 [2] 4d f6 [2] 4b c3 [2] 65 c3 [2] 5a df }

  condition:
    any of them
}