rule TTP_XOR_WriteProcessMemory_1c91 {
  strings:
    $key_1c91 = { 4b e3 [2] 79 c1 [2] 7f f4 [2] 51 f4 [2] 6e e8 }

  condition:
    any of them
}