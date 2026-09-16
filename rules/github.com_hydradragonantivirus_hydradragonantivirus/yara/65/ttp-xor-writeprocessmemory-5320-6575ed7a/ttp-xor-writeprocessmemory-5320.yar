rule TTP_XOR_WriteProcessMemory_5320 {
  strings:
    $key_5320 = { 04 52 [2] 36 70 [2] 30 45 [2] 1e 45 [2] 21 59 }

  condition:
    any of them
}