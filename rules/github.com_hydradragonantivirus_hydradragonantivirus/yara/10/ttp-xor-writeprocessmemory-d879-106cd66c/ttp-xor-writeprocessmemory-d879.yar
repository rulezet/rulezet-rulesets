rule TTP_XOR_WriteProcessMemory_d879 {
  strings:
    $key_d879 = { 8f 0b [2] bd 29 [2] bb 1c [2] 95 1c [2] aa 00 }

  condition:
    any of them
}