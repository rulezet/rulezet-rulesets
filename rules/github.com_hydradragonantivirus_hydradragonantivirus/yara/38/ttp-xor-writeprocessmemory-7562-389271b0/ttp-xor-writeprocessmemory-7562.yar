rule TTP_XOR_WriteProcessMemory_7562 {
  strings:
    $key_7562 = { 22 10 [2] 10 32 [2] 16 07 [2] 38 07 [2] 07 1b }

  condition:
    any of them
}