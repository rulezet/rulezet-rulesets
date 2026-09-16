rule TTP_XOR_WriteProcessMemory_0cc8 {
  strings:
    $key_0cc8 = { 5b ba [2] 69 98 [2] 6f ad [2] 41 ad [2] 7e b1 }

  condition:
    any of them
}