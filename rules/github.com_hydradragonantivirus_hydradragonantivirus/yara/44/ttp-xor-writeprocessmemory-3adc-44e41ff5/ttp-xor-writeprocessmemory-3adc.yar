rule TTP_XOR_WriteProcessMemory_3adc {
  strings:
    $key_3adc = { 6d ae [2] 5f 8c [2] 59 b9 [2] 77 b9 [2] 48 a5 }

  condition:
    any of them
}