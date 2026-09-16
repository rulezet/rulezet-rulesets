rule TTP_XOR_WriteProcessMemory_5b76 {
  strings:
    $key_5b76 = { 0c 04 [2] 3e 26 [2] 38 13 [2] 16 13 [2] 29 0f }

  condition:
    any of them
}