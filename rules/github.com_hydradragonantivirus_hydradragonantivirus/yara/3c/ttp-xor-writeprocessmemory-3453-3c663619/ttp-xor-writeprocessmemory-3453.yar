rule TTP_XOR_WriteProcessMemory_3453 {
  strings:
    $key_3453 = { 63 21 [2] 51 03 [2] 57 36 [2] 79 36 [2] 46 2a }

  condition:
    any of them
}