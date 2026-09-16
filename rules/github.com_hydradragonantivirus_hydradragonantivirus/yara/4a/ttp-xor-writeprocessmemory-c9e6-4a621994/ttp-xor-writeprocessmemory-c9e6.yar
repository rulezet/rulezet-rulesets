rule TTP_XOR_WriteProcessMemory_c9e6 {
  strings:
    $key_c9e6 = { 9e 94 [2] ac b6 [2] aa 83 [2] 84 83 [2] bb 9f }

  condition:
    any of them
}