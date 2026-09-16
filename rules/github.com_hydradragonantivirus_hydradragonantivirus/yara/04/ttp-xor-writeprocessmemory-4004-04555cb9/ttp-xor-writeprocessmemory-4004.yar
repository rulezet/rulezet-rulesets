rule TTP_XOR_WriteProcessMemory_4004 {
  strings:
    $key_4004 = { 17 76 [2] 25 54 [2] 23 61 [2] 0d 61 [2] 32 7d }

  condition:
    any of them
}