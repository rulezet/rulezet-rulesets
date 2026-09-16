rule TTP_XOR_WriteProcessMemory_3540 {
  strings:
    $key_3540 = { 62 32 [2] 50 10 [2] 56 25 [2] 78 25 [2] 47 39 }

  condition:
    any of them
}