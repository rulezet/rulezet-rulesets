rule TTP_XOR_WriteProcessMemory_0f06 {
  strings:
    $key_0f06 = { 58 74 [2] 6a 56 [2] 6c 63 [2] 42 63 [2] 7d 7f }

  condition:
    any of them
}