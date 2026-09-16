rule TTP_XOR_WriteProcessMemory_1941 {
  strings:
    $key_1941 = { 4e 33 [2] 7c 11 [2] 7a 24 [2] 54 24 [2] 6b 38 }

  condition:
    any of them
}