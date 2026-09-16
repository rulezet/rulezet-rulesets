rule TTP_XOR_WriteProcessMemory_1013 {
  strings:
    $key_1013 = { 47 61 [2] 75 43 [2] 73 76 [2] 5d 76 [2] 62 6a }

  condition:
    any of them
}