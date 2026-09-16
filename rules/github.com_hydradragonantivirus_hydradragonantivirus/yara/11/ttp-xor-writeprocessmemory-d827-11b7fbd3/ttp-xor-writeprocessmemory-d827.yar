rule TTP_XOR_WriteProcessMemory_d827 {
  strings:
    $key_d827 = { 8f 55 [2] bd 77 [2] bb 42 [2] 95 42 [2] aa 5e }

  condition:
    any of them
}