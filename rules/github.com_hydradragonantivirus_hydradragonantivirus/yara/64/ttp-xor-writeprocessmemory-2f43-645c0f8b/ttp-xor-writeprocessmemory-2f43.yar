rule TTP_XOR_WriteProcessMemory_2f43 {
  strings:
    $key_2f43 = { 78 31 [2] 4a 13 [2] 4c 26 [2] 62 26 [2] 5d 3a }

  condition:
    any of them
}