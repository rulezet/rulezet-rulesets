rule TTP_XOR_WriteProcessMemory_c906 {
  strings:
    $key_c906 = { 9e 74 [2] ac 56 [2] aa 63 [2] 84 63 [2] bb 7f }

  condition:
    any of them
}