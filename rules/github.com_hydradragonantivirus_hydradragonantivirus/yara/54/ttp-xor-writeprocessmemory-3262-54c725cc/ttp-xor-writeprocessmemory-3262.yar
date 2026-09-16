rule TTP_XOR_WriteProcessMemory_3262 {
  strings:
    $key_3262 = { 65 10 [2] 57 32 [2] 51 07 [2] 7f 07 [2] 40 1b }

  condition:
    any of them
}