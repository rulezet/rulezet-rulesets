rule TTP_XOR_WriteProcessMemory_e763 {
  strings:
    $key_e763 = { b0 11 [2] 82 33 [2] 84 06 [2] aa 06 [2] 95 1a }

  condition:
    any of them
}