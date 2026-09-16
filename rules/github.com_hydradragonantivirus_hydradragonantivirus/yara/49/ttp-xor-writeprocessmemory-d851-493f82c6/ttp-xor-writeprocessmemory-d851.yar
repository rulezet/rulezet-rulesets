rule TTP_XOR_WriteProcessMemory_d851 {
  strings:
    $key_d851 = { 8f 23 [2] bd 01 [2] bb 34 [2] 95 34 [2] aa 28 }

  condition:
    any of them
}