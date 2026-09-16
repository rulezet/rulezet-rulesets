rule TTP_XOR_WriteProcessMemory_3076 {
  strings:
    $key_3076 = { 67 04 [2] 55 26 [2] 53 13 [2] 7d 13 [2] 42 0f }

  condition:
    any of them
}