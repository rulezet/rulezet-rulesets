rule TTP_XOR_WriteProcessMemory_4311 {
  strings:
    $key_4311 = { 14 63 [2] 26 41 [2] 20 74 [2] 0e 74 [2] 31 68 }

  condition:
    any of them
}