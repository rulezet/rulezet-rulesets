rule TTP_XOR_WriteProcessMemory_1023 {
  strings:
    $key_1023 = { 47 51 [2] 75 73 [2] 73 46 [2] 5d 46 [2] 62 5a }

  condition:
    any of them
}