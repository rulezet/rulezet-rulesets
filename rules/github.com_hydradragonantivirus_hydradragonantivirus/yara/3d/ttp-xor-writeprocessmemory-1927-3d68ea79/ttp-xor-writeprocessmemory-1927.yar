rule TTP_XOR_WriteProcessMemory_1927 {
  strings:
    $key_1927 = { 4e 55 [2] 7c 77 [2] 7a 42 [2] 54 42 [2] 6b 5e }

  condition:
    any of them
}