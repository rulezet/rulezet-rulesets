rule TTP_XOR_WriteProcessMemory_7376 {
  strings:
    $key_7376 = { 24 04 [2] 16 26 [2] 10 13 [2] 3e 13 [2] 01 0f }

  condition:
    any of them
}