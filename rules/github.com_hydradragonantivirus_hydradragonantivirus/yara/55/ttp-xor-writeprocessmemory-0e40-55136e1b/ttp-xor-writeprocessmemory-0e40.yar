rule TTP_XOR_WriteProcessMemory_0e40 {
  strings:
    $key_0e40 = { 59 32 [2] 6b 10 [2] 6d 25 [2] 43 25 [2] 7c 39 }

  condition:
    any of them
}