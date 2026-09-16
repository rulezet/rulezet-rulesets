rule TTP_XOR_WriteProcessMemory_adc4 {
  strings:
    $key_adc4 = { fa b6 [2] c8 94 [2] ce a1 [2] e0 a1 [2] df bd }

  condition:
    any of them
}