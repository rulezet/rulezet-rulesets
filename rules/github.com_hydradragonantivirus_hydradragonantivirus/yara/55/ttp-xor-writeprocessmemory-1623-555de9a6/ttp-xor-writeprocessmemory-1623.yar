rule TTP_XOR_WriteProcessMemory_1623 {
  strings:
    $key_1623 = { 41 51 [2] 73 73 [2] 75 46 [2] 5b 46 [2] 64 5a }

  condition:
    any of them
}