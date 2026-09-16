rule TTP_XOR_WriteProcessMemory_3920 {
  strings:
    $key_3920 = { 6e 52 [2] 5c 70 [2] 5a 45 [2] 74 45 [2] 4b 59 }

  condition:
    any of them
}