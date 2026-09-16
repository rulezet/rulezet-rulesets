rule TTP_XOR_WriteProcessMemory_3963 {
  strings:
    $key_3963 = { 6e 11 [2] 5c 33 [2] 5a 06 [2] 74 06 [2] 4b 1a }

  condition:
    any of them
}