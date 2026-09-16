rule TTP_XOR_WriteProcessMemory_3662 {
  strings:
    $key_3662 = { 61 10 [2] 53 32 [2] 55 07 [2] 7b 07 [2] 44 1b }

  condition:
    any of them
}