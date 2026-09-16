rule TTP_XOR_WriteProcessMemory_1a61 {
  strings:
    $key_1a61 = { 4d 13 [2] 7f 31 [2] 79 04 [2] 57 04 [2] 68 18 }

  condition:
    any of them
}