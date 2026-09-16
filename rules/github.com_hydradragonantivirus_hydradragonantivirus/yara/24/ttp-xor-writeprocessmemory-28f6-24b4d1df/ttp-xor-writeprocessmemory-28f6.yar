rule TTP_XOR_WriteProcessMemory_28f6 {
  strings:
    $key_28f6 = { 7f 84 [2] 4d a6 [2] 4b 93 [2] 65 93 [2] 5a 8f }

  condition:
    any of them
}