rule TTP_XOR_WriteProcessMemory_5cc8 {
  strings:
    $key_5cc8 = { 0b ba [2] 39 98 [2] 3f ad [2] 11 ad [2] 2e b1 }

  condition:
    any of them
}