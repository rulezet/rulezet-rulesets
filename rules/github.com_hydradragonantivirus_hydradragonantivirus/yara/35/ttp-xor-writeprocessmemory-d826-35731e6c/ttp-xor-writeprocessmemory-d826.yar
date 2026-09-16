rule TTP_XOR_WriteProcessMemory_d826 {
  strings:
    $key_d826 = { 8f 54 [2] bd 76 [2] bb 43 [2] 95 43 [2] aa 5f }

  condition:
    any of them
}