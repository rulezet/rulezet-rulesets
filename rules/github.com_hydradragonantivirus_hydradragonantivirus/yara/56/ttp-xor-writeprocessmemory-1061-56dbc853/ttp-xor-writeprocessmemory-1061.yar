rule TTP_XOR_WriteProcessMemory_1061 {
  strings:
    $key_1061 = { 47 13 [2] 75 31 [2] 73 04 [2] 5d 04 [2] 62 18 }

  condition:
    any of them
}