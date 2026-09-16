rule TTP_XOR_WriteProcessMemory_2176 {
  strings:
    $key_2176 = { 76 04 [2] 44 26 [2] 42 13 [2] 6c 13 [2] 53 0f }

  condition:
    any of them
}