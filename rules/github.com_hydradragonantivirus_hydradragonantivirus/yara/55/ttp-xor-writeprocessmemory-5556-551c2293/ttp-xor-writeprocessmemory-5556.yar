rule TTP_XOR_WriteProcessMemory_5556 {
  strings:
    $key_5556 = { 02 24 [2] 30 06 [2] 36 33 [2] 18 33 [2] 27 2f }

  condition:
    any of them
}