rule TTP_XOR_WriteProcessMemory_1cc8 {
  strings:
    $key_1cc8 = { 4b ba [2] 79 98 [2] 7f ad [2] 51 ad [2] 6e b1 }

  condition:
    any of them
}