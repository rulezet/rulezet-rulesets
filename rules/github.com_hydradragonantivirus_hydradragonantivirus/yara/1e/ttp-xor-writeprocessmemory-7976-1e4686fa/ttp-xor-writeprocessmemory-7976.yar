rule TTP_XOR_WriteProcessMemory_7976 {
  strings:
    $key_7976 = { 2e 04 [2] 1c 26 [2] 1a 13 [2] 34 13 [2] 0b 0f }

  condition:
    any of them
}