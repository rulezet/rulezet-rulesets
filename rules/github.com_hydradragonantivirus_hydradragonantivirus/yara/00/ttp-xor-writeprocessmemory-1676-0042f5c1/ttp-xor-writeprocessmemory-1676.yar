rule TTP_XOR_WriteProcessMemory_1676 {
  strings:
    $key_1676 = { 41 04 [2] 73 26 [2] 75 13 [2] 5b 13 [2] 64 0f }

  condition:
    any of them
}