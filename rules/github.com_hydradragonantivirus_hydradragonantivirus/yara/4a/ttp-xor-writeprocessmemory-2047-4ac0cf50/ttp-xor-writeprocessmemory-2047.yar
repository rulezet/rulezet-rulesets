rule TTP_XOR_WriteProcessMemory_2047 {
  strings:
    $key_2047 = { 77 35 [2] 45 17 [2] 43 22 [2] 6d 22 [2] 52 3e }

  condition:
    any of them
}