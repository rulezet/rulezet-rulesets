rule TTP_XOR_WriteProcessMemory_5adc {
  strings:
    $key_5adc = { 0d ae [2] 3f 8c [2] 39 b9 [2] 17 b9 [2] 28 a5 }

  condition:
    any of them
}