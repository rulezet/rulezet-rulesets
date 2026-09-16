rule TTP_XOR_WriteProcessMemory_c956 {
  strings:
    $key_c956 = { 9e 24 [2] ac 06 [2] aa 33 [2] 84 33 [2] bb 2f }

  condition:
    any of them
}