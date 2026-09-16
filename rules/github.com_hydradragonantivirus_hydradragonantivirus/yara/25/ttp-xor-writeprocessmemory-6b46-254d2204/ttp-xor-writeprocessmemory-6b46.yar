rule TTP_XOR_WriteProcessMemory_6b46 {
  strings:
    $key_6b46 = { 3c 34 [2] 0e 16 [2] 08 23 [2] 26 23 [2] 19 3f }

  condition:
    any of them
}