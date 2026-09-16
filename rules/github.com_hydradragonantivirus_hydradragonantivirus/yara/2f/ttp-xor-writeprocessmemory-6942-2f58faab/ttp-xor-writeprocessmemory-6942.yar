rule TTP_XOR_WriteProcessMemory_6942 {
  strings:
    $key_6942 = { 3e 30 [2] 0c 12 [2] 0a 27 [2] 24 27 [2] 1b 3b }

  condition:
    any of them
}