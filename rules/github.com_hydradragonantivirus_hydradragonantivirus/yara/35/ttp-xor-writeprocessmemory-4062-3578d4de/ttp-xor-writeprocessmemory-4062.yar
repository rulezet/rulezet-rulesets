rule TTP_XOR_WriteProcessMemory_4062 {
  strings:
    $key_4062 = { 17 10 [2] 25 32 [2] 23 07 [2] 0d 07 [2] 32 1b }

  condition:
    any of them
}