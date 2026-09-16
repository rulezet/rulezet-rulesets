rule TTP_XOR_WriteProcessMemory_1004 {
  strings:
    $key_1004 = { 47 76 [2] 75 54 [2] 73 61 [2] 5d 61 [2] 62 7d }

  condition:
    any of them
}