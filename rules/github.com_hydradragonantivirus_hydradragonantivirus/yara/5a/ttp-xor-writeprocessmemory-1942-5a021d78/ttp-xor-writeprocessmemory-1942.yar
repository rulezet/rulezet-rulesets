rule TTP_XOR_WriteProcessMemory_1942 {
  strings:
    $key_1942 = { 4e 30 [2] 7c 12 [2] 7a 27 [2] 54 27 [2] 6b 3b }

  condition:
    any of them
}