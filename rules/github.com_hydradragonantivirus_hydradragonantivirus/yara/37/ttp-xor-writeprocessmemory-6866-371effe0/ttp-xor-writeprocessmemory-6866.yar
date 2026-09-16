rule TTP_XOR_WriteProcessMemory_6866 {
  strings:
    $key_6866 = { 3f 14 [2] 0d 36 [2] 0b 03 [2] 25 03 [2] 1a 1f }

  condition:
    any of them
}