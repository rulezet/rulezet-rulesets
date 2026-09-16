rule TTP_XOR_WriteProcessMemory_2b43 {
  strings:
    $key_2b43 = { 7c 31 [2] 4e 13 [2] 48 26 [2] 66 26 [2] 59 3a }

  condition:
    any of them
}