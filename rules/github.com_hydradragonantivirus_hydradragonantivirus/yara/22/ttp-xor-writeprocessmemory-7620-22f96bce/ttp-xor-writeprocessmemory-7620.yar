rule TTP_XOR_WriteProcessMemory_7620 {
  strings:
    $key_7620 = { 21 52 [2] 13 70 [2] 15 45 [2] 3b 45 [2] 04 59 }

  condition:
    any of them
}