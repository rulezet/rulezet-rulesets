rule TTP_XOR_WriteProcessMemory_dec5 {
  strings:
    $key_dec5 = { 89 b7 [2] bb 95 [2] bd a0 [2] 93 a0 [2] ac bc }

  condition:
    any of them
}