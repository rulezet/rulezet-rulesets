rule TTP_XOR_WriteProcessMemory_d822 {
  strings:
    $key_d822 = { 8f 50 [2] bd 72 [2] bb 47 [2] 95 47 [2] aa 5b }

  condition:
    any of them
}