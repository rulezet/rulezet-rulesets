rule TTP_XOR_WriteProcessMemory_6b56 {
  strings:
    $key_6b56 = { 3c 24 [2] 0e 06 [2] 08 33 [2] 26 33 [2] 19 2f }

  condition:
    any of them
}