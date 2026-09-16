rule TTP_XOR_WriteProcessMemory_1c61 {
  strings:
    $key_1c61 = { 4b 13 [2] 79 31 [2] 7f 04 [2] 51 04 [2] 6e 18 }

  condition:
    any of them
}