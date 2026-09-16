rule TTP_XOR_WriteProcessMemory_48a6 {
  strings:
    $key_48a6 = { 1f d4 [2] 2d f6 [2] 2b c3 [2] 05 c3 [2] 3a df }

  condition:
    any of them
}