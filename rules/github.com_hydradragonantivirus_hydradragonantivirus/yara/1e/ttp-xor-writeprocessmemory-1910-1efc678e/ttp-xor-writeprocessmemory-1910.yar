rule TTP_XOR_WriteProcessMemory_1910 {
  strings:
    $key_1910 = { 4e 62 [2] 7c 40 [2] 7a 75 [2] 54 75 [2] 6b 69 }

  condition:
    any of them
}