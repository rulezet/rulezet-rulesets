rule TTP_XOR_WriteProcessMemory_1963 {
  strings:
    $key_1963 = { 4e 11 [2] 7c 33 [2] 7a 06 [2] 54 06 [2] 6b 1a }

  condition:
    any of them
}