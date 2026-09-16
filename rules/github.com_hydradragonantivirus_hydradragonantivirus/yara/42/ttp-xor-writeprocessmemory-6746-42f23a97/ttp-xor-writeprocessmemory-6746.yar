rule TTP_XOR_WriteProcessMemory_6746 {
  strings:
    $key_6746 = { 30 34 [2] 02 16 [2] 04 23 [2] 2a 23 [2] 15 3f }

  condition:
    any of them
}