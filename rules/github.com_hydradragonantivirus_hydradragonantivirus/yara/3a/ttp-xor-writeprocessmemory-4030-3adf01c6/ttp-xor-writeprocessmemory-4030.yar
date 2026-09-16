rule TTP_XOR_WriteProcessMemory_4030 {
  strings:
    $key_4030 = { 17 42 [2] 25 60 [2] 23 55 [2] 0d 55 [2] 32 49 }

  condition:
    any of them
}