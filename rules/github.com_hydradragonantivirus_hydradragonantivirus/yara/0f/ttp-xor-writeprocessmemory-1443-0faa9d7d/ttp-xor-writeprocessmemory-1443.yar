rule TTP_XOR_WriteProcessMemory_1443 {
  strings:
    $key_1443 = { 43 31 [2] 71 13 [2] 77 26 [2] 59 26 [2] 66 3a }

  condition:
    any of them
}