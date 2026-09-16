rule TTP_XOR_WriteProcessMemory_0e62 {
  strings:
    $key_0e62 = { 59 10 [2] 6b 32 [2] 6d 07 [2] 43 07 [2] 7c 1b }

  condition:
    any of them
}