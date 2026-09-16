rule TTP_XOR_WriteProcessMemory_4604 {
  strings:
    $key_4604 = { 11 76 [2] 23 54 [2] 25 61 [2] 0b 61 [2] 34 7d }

  condition:
    any of them
}