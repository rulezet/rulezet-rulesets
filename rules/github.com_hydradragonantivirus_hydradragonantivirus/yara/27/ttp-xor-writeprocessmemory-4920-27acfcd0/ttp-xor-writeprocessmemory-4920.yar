rule TTP_XOR_WriteProcessMemory_4920 {
  strings:
    $key_4920 = { 1e 52 [2] 2c 70 [2] 2a 45 [2] 04 45 [2] 3b 59 }

  condition:
    any of them
}