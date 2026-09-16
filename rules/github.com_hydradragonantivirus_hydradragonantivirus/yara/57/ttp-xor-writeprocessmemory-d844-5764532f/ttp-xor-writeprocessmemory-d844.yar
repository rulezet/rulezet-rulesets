rule TTP_XOR_WriteProcessMemory_d844 {
  strings:
    $key_d844 = { 8f 36 [2] bd 14 [2] bb 21 [2] 95 21 [2] aa 3d }

  condition:
    any of them
}