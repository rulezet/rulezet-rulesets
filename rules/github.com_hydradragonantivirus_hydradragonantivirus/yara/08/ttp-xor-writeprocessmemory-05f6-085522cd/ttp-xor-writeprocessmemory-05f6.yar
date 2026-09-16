rule TTP_XOR_WriteProcessMemory_05f6 {
  strings:
    $key_05f6 = { 52 84 [2] 60 a6 [2] 66 93 [2] 48 93 [2] 77 8f }

  condition:
    any of them
}