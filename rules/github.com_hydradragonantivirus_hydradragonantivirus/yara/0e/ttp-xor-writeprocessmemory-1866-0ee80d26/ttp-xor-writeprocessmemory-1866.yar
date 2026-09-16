rule TTP_XOR_WriteProcessMemory_1866 {
  strings:
    $key_1866 = { 4f 14 [2] 7d 36 [2] 7b 03 [2] 55 03 [2] 6a 1f }

  condition:
    any of them
}