rule TTP_XOR_WriteProcessMemory_0e42 {
  strings:
    $key_0e42 = { 59 30 [2] 6b 12 [2] 6d 27 [2] 43 27 [2] 7c 3b }

  condition:
    any of them
}