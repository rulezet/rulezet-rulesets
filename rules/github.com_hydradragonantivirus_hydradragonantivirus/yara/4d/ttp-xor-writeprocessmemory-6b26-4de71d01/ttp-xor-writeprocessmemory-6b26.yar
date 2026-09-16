rule TTP_XOR_WriteProcessMemory_6b26 {
  strings:
    $key_6b26 = { 3c 54 [2] 0e 76 [2] 08 43 [2] 26 43 [2] 19 5f }

  condition:
    any of them
}