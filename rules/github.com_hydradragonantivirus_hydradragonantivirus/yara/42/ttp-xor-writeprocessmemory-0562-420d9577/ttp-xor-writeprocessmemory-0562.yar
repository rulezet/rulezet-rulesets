rule TTP_XOR_WriteProcessMemory_0562 {
  strings:
    $key_0562 = { 52 10 [2] 60 32 [2] 66 07 [2] 48 07 [2] 77 1b }

  condition:
    any of them
}