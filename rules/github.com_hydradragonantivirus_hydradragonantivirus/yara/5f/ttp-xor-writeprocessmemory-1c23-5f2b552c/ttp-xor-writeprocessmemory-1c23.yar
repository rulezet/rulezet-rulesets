rule TTP_XOR_WriteProcessMemory_1c23 {
  strings:
    $key_1c23 = { 4b 51 [2] 79 73 [2] 7f 46 [2] 51 46 [2] 6e 5a }

  condition:
    any of them
}