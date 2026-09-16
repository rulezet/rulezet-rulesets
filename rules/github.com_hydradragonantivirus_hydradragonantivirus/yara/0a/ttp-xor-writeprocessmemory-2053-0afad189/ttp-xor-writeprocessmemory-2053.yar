rule TTP_XOR_WriteProcessMemory_2053 {
  strings:
    $key_2053 = { 77 21 [2] 45 03 [2] 43 36 [2] 6d 36 [2] 52 2a }

  condition:
    any of them
}