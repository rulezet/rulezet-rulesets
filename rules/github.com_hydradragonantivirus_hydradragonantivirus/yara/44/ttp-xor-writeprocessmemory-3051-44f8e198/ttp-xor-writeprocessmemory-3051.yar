rule TTP_XOR_WriteProcessMemory_3051 {
  strings:
    $key_3051 = { 67 23 [2] 55 01 [2] 53 34 [2] 7d 34 [2] 42 28 }

  condition:
    any of them
}