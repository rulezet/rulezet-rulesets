rule TTP_XOR_WriteProcessMemory_6453 {
  strings:
    $key_6453 = { 33 21 [2] 01 03 [2] 07 36 [2] 29 36 [2] 16 2a }

  condition:
    any of them
}