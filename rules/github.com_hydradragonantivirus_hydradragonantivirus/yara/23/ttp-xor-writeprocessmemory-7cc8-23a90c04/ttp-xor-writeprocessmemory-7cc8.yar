rule TTP_XOR_WriteProcessMemory_7cc8 {
  strings:
    $key_7cc8 = { 2b ba [2] 19 98 [2] 1f ad [2] 31 ad [2] 0e b1 }

  condition:
    any of them
}