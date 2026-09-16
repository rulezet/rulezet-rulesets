rule TTP_XOR_WriteProcessMemory_2920 {
  strings:
    $key_2920 = { 7e 52 [2] 4c 70 [2] 4a 45 [2] 64 45 [2] 5b 59 }

  condition:
    any of them
}