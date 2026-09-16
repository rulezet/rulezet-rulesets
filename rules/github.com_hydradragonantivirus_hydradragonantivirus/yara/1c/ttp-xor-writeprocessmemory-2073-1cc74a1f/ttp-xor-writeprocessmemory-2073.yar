rule TTP_XOR_WriteProcessMemory_2073 {
  strings:
    $key_2073 = { 77 01 [2] 45 23 [2] 43 16 [2] 6d 16 [2] 52 0a }

  condition:
    any of them
}