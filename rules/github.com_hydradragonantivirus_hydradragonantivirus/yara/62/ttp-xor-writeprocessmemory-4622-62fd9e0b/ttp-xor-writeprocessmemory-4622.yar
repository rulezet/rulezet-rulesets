rule TTP_XOR_WriteProcessMemory_4622 {
  strings:
    $key_4622 = { 11 50 [2] 23 72 [2] 25 47 [2] 0b 47 [2] 34 5b }

  condition:
    any of them
}