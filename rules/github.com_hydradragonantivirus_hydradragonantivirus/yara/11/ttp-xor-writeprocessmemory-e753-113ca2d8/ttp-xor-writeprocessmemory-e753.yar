rule TTP_XOR_WriteProcessMemory_e753 {
  strings:
    $key_e753 = { b0 21 [2] 82 03 [2] 84 36 [2] aa 36 [2] 95 2a }

  condition:
    any of them
}