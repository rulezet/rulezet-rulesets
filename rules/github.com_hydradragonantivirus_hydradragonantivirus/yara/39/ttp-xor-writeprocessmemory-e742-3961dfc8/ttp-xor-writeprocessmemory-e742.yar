rule TTP_XOR_WriteProcessMemory_e742 {
  strings:
    $key_e742 = { b0 30 [2] 82 12 [2] 84 27 [2] aa 27 [2] 95 3b }

  condition:
    any of them
}