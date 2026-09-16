rule TTP_XOR_WriteProcessMemory_1d20 {
  strings:
    $key_1d20 = { 4a 52 [2] 78 70 [2] 7e 45 [2] 50 45 [2] 6f 59 }

  condition:
    any of them
}