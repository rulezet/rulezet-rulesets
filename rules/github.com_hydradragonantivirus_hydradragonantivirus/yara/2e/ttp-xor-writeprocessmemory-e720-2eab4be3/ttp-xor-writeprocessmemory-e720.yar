rule TTP_XOR_WriteProcessMemory_e720 {
  strings:
    $key_e720 = { b0 52 [2] 82 70 [2] 84 45 [2] aa 45 [2] 95 59 }

  condition:
    any of them
}