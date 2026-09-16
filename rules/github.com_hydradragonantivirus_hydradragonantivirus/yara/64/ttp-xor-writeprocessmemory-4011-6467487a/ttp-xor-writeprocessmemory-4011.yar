rule TTP_XOR_WriteProcessMemory_4011 {
  strings:
    $key_4011 = { 17 63 [2] 25 41 [2] 23 74 [2] 0d 74 [2] 32 68 }

  condition:
    any of them
}