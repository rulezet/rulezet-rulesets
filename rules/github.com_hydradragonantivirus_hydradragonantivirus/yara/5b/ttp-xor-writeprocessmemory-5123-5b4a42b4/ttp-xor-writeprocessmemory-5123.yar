rule TTP_XOR_WriteProcessMemory_5123 {
  strings:
    $key_5123 = { 06 51 [2] 34 73 [2] 32 46 [2] 1c 46 [2] 23 5a }

  condition:
    any of them
}