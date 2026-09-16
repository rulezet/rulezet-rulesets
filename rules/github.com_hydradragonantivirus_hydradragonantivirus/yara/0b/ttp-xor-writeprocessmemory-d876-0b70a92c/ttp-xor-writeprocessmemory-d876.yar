rule TTP_XOR_WriteProcessMemory_d876 {
  strings:
    $key_d876 = { 8f 04 [2] bd 26 [2] bb 13 [2] 95 13 [2] aa 0f }

  condition:
    any of them
}