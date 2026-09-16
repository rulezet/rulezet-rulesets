rule TTP_XOR_WriteProcessMemory_6e26 {
  strings:
    $key_6e26 = { 39 54 [2] 0b 76 [2] 0d 43 [2] 23 43 [2] 1c 5f }

  condition:
    any of them
}