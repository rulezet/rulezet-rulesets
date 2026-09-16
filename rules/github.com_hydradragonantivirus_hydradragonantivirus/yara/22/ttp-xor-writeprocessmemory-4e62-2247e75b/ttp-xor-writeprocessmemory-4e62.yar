rule TTP_XOR_WriteProcessMemory_4e62 {
  strings:
    $key_4e62 = { 19 10 [2] 2b 32 [2] 2d 07 [2] 03 07 [2] 3c 1b }

  condition:
    any of them
}