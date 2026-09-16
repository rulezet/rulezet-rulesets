rule TTP_XOR_WriteProcessMemory_61e9 {
  strings:
    $key_61e9 = { 36 9b [2] 04 b9 [2] 02 8c [2] 2c 8c [2] 13 90 }

  condition:
    any of them
}