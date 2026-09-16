rule TTP_XOR_WriteProcessMemory_c9e4 {
  strings:
    $key_c9e4 = { 9e 96 [2] ac b4 [2] aa 81 [2] 84 81 [2] bb 9d }

  condition:
    any of them
}