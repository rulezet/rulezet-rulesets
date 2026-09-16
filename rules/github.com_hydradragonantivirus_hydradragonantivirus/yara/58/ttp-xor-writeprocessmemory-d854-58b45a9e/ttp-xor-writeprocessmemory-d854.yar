rule TTP_XOR_WriteProcessMemory_d854 {
  strings:
    $key_d854 = { 8f 26 [2] bd 04 [2] bb 31 [2] 95 31 [2] aa 2d }

  condition:
    any of them
}