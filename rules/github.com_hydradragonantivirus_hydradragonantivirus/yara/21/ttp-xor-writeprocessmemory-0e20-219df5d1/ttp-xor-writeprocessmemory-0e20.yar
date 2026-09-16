rule TTP_XOR_WriteProcessMemory_0e20 {
  strings:
    $key_0e20 = { 59 52 [2] 6b 70 [2] 6d 45 [2] 43 45 [2] 7c 59 }

  condition:
    any of them
}