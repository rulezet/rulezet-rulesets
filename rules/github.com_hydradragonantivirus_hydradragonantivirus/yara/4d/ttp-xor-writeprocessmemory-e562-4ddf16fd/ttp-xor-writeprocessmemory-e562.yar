rule TTP_XOR_WriteProcessMemory_e562 {
  strings:
    $key_e562 = { b2 10 [2] 80 32 [2] 86 07 [2] a8 07 [2] 97 1b }

  condition:
    any of them
}