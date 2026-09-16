rule TTP_XOR_WriteProcessMemory_c917 {
  strings:
    $key_c917 = { 9e 65 [2] ac 47 [2] aa 72 [2] 84 72 [2] bb 6e }

  condition:
    any of them
}