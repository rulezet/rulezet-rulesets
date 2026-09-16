rule TTP_XOR_WriteProcessMemory_d877 {
  strings:
    $key_d877 = { 8f 05 [2] bd 27 [2] bb 12 [2] 95 12 [2] aa 0e }

  condition:
    any of them
}