rule TTP_XOR_WriteProcessMemory_28e6 {
  strings:
    $key_28e6 = { 7f 94 [2] 4d b6 [2] 4b 83 [2] 65 83 [2] 5a 9f }

  condition:
    any of them
}