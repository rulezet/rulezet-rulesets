rule TTP_XOR_WriteProcessMemory_2e43 {
  strings:
    $key_2e43 = { 79 31 [2] 4b 13 [2] 4d 26 [2] 63 26 [2] 5c 3a }

  condition:
    any of them
}