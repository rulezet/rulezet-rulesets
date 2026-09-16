rule TTP_XOR_WriteProcessMemory_6f43 {
  strings:
    $key_6f43 = { 38 31 [2] 0a 13 [2] 0c 26 [2] 22 26 [2] 1d 3a }

  condition:
    any of them
}