rule TTP_XOR_WriteProcessMemory_5120 {
  strings:
    $key_5120 = { 06 52 [2] 34 70 [2] 32 45 [2] 1c 45 [2] 23 59 }

  condition:
    any of them
}