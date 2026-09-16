rule TTP_XOR_WriteProcessMemory_d836 {
  strings:
    $key_d836 = { 8f 44 [2] bd 66 [2] bb 53 [2] 95 53 [2] aa 4f }

  condition:
    any of them
}