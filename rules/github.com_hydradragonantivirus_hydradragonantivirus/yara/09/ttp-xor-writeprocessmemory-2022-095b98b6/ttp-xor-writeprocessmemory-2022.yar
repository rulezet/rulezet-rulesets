rule TTP_XOR_WriteProcessMemory_2022 {
  strings:
    $key_2022 = { 77 50 [2] 45 72 [2] 43 47 [2] 6d 47 [2] 52 5b }

  condition:
    any of them
}