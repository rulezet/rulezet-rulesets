rule TTP_XOR_WriteProcessMemory_d866 {
  strings:
    $key_d866 = { 8f 14 [2] bd 36 [2] bb 03 [2] 95 03 [2] aa 1f }

  condition:
    any of them
}