rule TTP_XOR_WriteProcessMemory_1c32 {
  strings:
    $key_1c32 = { 4b 40 [2] 79 62 [2] 7f 57 [2] 51 57 [2] 6e 4b }

  condition:
    any of them
}