rule TTP_XOR_WriteProcessMemory_5502 {
  strings:
    $key_5502 = { 02 70 [2] 30 52 [2] 36 67 [2] 18 67 [2] 27 7b }

  condition:
    any of them
}