rule TTP_XOR_WriteProcessMemory_4051 {
  strings:
    $key_4051 = { 17 23 [2] 25 01 [2] 23 34 [2] 0d 34 [2] 32 28 }

  condition:
    any of them
}