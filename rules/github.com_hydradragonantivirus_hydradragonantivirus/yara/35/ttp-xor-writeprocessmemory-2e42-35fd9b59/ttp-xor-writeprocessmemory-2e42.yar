rule TTP_XOR_WriteProcessMemory_2e42 {
  strings:
    $key_2e42 = { 79 30 [2] 4b 12 [2] 4d 27 [2] 63 27 [2] 5c 3b }

  condition:
    any of them
}