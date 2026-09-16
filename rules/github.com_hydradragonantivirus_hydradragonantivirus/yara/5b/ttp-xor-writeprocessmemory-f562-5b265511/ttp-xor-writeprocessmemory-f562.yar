rule TTP_XOR_WriteProcessMemory_f562 {
  strings:
    $key_f562 = { a2 10 [2] 90 32 [2] 96 07 [2] b8 07 [2] 87 1b }

  condition:
    any of them
}