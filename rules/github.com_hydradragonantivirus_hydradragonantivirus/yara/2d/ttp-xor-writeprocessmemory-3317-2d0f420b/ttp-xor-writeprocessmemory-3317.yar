rule TTP_XOR_WriteProcessMemory_3317 {
  strings:
    $key_3317 = { 64 65 [2] 56 47 [2] 50 72 [2] 7e 72 [2] 41 6e }

  condition:
    any of them
}