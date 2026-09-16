rule TTP_XOR_WriteProcessMemory_2067 {
  strings:
    $key_2067 = { 77 15 [2] 45 37 [2] 43 02 [2] 6d 02 [2] 52 1e }

  condition:
    any of them
}