rule TTP_XOR_WriteProcessMemory_c957 {
  strings:
    $key_c957 = { 9e 25 [2] ac 07 [2] aa 32 [2] 84 32 [2] bb 2e }

  condition:
    any of them
}