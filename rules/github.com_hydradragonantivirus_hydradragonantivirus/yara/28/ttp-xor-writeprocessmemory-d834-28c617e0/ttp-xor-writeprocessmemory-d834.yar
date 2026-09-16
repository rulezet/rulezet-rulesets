rule TTP_XOR_WriteProcessMemory_d834 {
  strings:
    $key_d834 = { 8f 46 [2] bd 64 [2] bb 51 [2] 95 51 [2] aa 4d }

  condition:
    any of them
}