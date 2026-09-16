rule TTP_XOR_WriteProcessMemory_7e43 {
  strings:
    $key_7e43 = { 29 31 [2] 1b 13 [2] 1d 26 [2] 33 26 [2] 0c 3a }

  condition:
    any of them
}