rule TTP_XOR_WriteProcessMemory_68a6 {
  strings:
    $key_68a6 = { 3f d4 [2] 0d f6 [2] 0b c3 [2] 25 c3 [2] 1a df }

  condition:
    any of them
}