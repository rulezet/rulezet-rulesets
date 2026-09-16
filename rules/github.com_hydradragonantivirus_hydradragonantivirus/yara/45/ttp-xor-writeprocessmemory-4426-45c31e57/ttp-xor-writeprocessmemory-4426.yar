rule TTP_XOR_WriteProcessMemory_4426 {
  strings:
    $key_4426 = { 13 54 [2] 21 76 [2] 27 43 [2] 09 43 [2] 36 5f }

  condition:
    any of them
}