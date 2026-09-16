rule TTP_XOR_WriteProcessMemory_c902 {
  strings:
    $key_c902 = { 9e 70 [2] ac 52 [2] aa 67 [2] 84 67 [2] bb 7b }

  condition:
    any of them
}