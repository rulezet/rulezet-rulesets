rule TTP_XOR_WriteProcessMemory_2d62 {
  strings:
    $key_2d62 = { 7a 10 [2] 48 32 [2] 4e 07 [2] 60 07 [2] 5f 1b }

  condition:
    any of them
}