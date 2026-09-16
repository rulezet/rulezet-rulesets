rule TTP_XOR_WriteProcessMemory_c963 {
  strings:
    $key_c963 = { 9e 11 [2] ac 33 [2] aa 06 [2] 84 06 [2] bb 1a }

  condition:
    any of them
}