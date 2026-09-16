rule TTP_XOR_WriteProcessMemory_2173 {
  strings:
    $key_2173 = { 76 01 [2] 44 23 [2] 42 16 [2] 6c 16 [2] 53 0a }

  condition:
    any of them
}