rule TTP_XOR_WriteProcessMemory_e866 {
  strings:
    $key_e866 = { bf 14 [2] 8d 36 [2] 8b 03 [2] a5 03 [2] 9a 1f }

  condition:
    any of them
}