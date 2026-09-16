rule TTP_XOR_WriteProcessMemory_6e76 {
  strings:
    $key_6e76 = { 39 04 [2] 0b 26 [2] 0d 13 [2] 23 13 [2] 1c 0f }

  condition:
    any of them
}