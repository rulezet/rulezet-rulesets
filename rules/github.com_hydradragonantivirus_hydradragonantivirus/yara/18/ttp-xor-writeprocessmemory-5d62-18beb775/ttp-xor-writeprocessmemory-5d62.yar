rule TTP_XOR_WriteProcessMemory_5d62 {
  strings:
    $key_5d62 = { 0a 10 [2] 38 32 [2] 3e 07 [2] 10 07 [2] 2f 1b }

  condition:
    any of them
}