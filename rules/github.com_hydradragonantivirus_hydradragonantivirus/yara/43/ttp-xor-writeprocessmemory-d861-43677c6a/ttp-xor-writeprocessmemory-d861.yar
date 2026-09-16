rule TTP_XOR_WriteProcessMemory_d861 {
  strings:
    $key_d861 = { 8f 13 [2] bd 31 [2] bb 04 [2] 95 04 [2] aa 18 }

  condition:
    any of them
}