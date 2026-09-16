rule TTP_XOR_WriteProcessMemory_5062 {
  strings:
    $key_5062 = { 07 10 [2] 35 32 [2] 33 07 [2] 1d 07 [2] 22 1b }

  condition:
    any of them
}