rule TTP_XOR_WriteProcessMemory_2e62 {
  strings:
    $key_2e62 = { 79 10 [2] 4b 32 [2] 4d 07 [2] 63 07 [2] 5c 1b }

  condition:
    any of them
}