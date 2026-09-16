rule TTP_XOR_WriteProcessMemory_5523 {
  strings:
    $key_5523 = { 02 51 [2] 30 73 [2] 36 46 [2] 18 46 [2] 27 5a }

  condition:
    any of them
}