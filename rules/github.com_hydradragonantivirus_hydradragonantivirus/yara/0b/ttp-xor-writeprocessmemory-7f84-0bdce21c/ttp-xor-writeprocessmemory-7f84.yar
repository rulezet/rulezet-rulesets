rule TTP_XOR_WriteProcessMemory_7f84 {
  strings:
    $key_7f84 = { 28 f6 [2] 1a d4 [2] 1c e1 [2] 32 e1 [2] 0d fd }

  condition:
    any of them
}