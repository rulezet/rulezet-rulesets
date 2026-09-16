rule TTP_XOR_WriteProcessMemory_0d62 {
  strings:
    $key_0d62 = { 5a 10 [2] 68 32 [2] 6e 07 [2] 40 07 [2] 7f 1b }

  condition:
    any of them
}