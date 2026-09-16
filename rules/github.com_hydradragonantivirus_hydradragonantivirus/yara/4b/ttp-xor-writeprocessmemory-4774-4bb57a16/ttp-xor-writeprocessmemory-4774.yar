rule TTP_XOR_WriteProcessMemory_4774 {
  strings:
    $key_4774 = { 10 06 [2] 22 24 [2] 24 11 [2] 0a 11 [2] 35 0d }

  condition:
    any of them
}