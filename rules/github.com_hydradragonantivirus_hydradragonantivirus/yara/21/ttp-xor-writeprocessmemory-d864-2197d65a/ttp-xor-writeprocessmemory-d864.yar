rule TTP_XOR_WriteProcessMemory_d864 {
  strings:
    $key_d864 = { 8f 16 [2] bd 34 [2] bb 01 [2] 95 01 [2] aa 1d }

  condition:
    any of them
}