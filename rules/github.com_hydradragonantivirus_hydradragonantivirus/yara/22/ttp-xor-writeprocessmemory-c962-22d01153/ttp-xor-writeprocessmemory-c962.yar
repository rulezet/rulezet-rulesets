rule TTP_XOR_WriteProcessMemory_c962 {
  strings:
    $key_c962 = { 9e 10 [2] ac 32 [2] aa 07 [2] 84 07 [2] bb 1b }

  condition:
    any of them
}