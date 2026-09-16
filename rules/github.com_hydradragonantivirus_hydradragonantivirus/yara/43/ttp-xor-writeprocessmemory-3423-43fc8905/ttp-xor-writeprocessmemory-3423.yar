rule TTP_XOR_WriteProcessMemory_3423 {
  strings:
    $key_3423 = { 63 51 [2] 51 73 [2] 57 46 [2] 79 46 [2] 46 5a }

  condition:
    any of them
}