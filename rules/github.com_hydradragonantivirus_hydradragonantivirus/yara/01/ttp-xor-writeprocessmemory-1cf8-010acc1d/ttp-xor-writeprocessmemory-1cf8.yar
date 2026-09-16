rule TTP_XOR_WriteProcessMemory_1cf8 {
  strings:
    $key_1cf8 = { 4b 8a [2] 79 a8 [2] 7f 9d [2] 51 9d [2] 6e 81 }

  condition:
    any of them
}