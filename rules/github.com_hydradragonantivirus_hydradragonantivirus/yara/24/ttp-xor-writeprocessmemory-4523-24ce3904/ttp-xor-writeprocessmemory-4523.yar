rule TTP_XOR_WriteProcessMemory_4523 {
  strings:
    $key_4523 = { 12 51 [2] 20 73 [2] 26 46 [2] 08 46 [2] 37 5a }

  condition:
    any of them
}