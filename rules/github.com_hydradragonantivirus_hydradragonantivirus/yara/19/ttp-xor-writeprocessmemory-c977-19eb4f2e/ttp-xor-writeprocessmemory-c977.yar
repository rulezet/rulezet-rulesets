rule TTP_XOR_WriteProcessMemory_c977 {
  strings:
    $key_c977 = { 9e 05 [2] ac 27 [2] aa 12 [2] 84 12 [2] bb 0e }

  condition:
    any of them
}