rule TTP_XOR_WriteProcessMemory_3062 {
  strings:
    $key_3062 = { 67 10 [2] 55 32 [2] 53 07 [2] 7d 07 [2] 42 1b }

  condition:
    any of them
}