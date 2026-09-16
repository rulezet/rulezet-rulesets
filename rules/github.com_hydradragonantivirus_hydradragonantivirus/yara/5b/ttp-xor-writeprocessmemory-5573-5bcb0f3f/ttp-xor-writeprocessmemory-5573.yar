rule TTP_XOR_WriteProcessMemory_5573 {
  strings:
    $key_5573 = { 02 01 [2] 30 23 [2] 36 16 [2] 18 16 [2] 27 0a }

  condition:
    any of them
}