rule TTP_XOR_WriteProcessMemory_1931 {
  strings:
    $key_1931 = { 4e 43 [2] 7c 61 [2] 7a 54 [2] 54 54 [2] 6b 48 }

  condition:
    any of them
}