rule TTP_XOR_WriteProcessMemory_c955 {
  strings:
    $key_c955 = { 9e 27 [2] ac 05 [2] aa 30 [2] 84 30 [2] bb 2c }

  condition:
    any of them
}