rule TTP_XOR_WriteProcessMemory_8adc {
  strings:
    $key_8adc = { dd ae [2] ef 8c [2] e9 b9 [2] c7 b9 [2] f8 a5 }

  condition:
    any of them
}