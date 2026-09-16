rule TTP_XOR_WriteProcessMemory_1a60 {
  strings:
    $key_1a60 = { 4d 12 [2] 7f 30 [2] 79 05 [2] 57 05 [2] 68 19 }

  condition:
    any of them
}