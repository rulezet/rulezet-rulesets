rule TTP_XOR_WriteProcessMemory_0e60 {
  strings:
    $key_0e60 = { 59 12 [2] 6b 30 [2] 6d 05 [2] 43 05 [2] 7c 19 }

  condition:
    any of them
}