rule TTP_XOR_WriteProcessMemory_2cc8 {
  strings:
    $key_2cc8 = { 7b ba [2] 49 98 [2] 4f ad [2] 61 ad [2] 5e b1 }

  condition:
    any of them
}