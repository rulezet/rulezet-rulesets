rule TTP_XOR_WriteProcessMemory_7320 {
  strings:
    $key_7320 = { 24 52 [2] 16 70 [2] 10 45 [2] 3e 45 [2] 01 59 }

  condition:
    any of them
}