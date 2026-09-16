rule TTP_XOR_WriteProcessMemory_2241 {
  strings:
    $key_2241 = { 75 33 [2] 47 11 [2] 41 24 [2] 6f 24 [2] 50 38 }

  condition:
    any of them
}