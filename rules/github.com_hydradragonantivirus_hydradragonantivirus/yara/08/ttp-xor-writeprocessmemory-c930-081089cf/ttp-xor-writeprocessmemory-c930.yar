rule TTP_XOR_WriteProcessMemory_c930 {
  strings:
    $key_c930 = { 9e 42 [2] ac 60 [2] aa 55 [2] 84 55 [2] bb 49 }

  condition:
    any of them
}