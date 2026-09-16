rule TTP_XOR_WriteProcessMemory_d810 {
  strings:
    $key_d810 = { 8f 62 [2] bd 40 [2] bb 75 [2] 95 75 [2] aa 69 }

  condition:
    any of them
}