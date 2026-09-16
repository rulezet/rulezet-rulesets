rule TTP_XOR_WriteProcessMemory_4adc {
  strings:
    $key_4adc = { 1d ae [2] 2f 8c [2] 29 b9 [2] 07 b9 [2] 38 a5 }

  condition:
    any of them
}