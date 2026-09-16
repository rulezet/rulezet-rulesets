rule TTP_XOR_WriteProcessMemory_2020 {
  strings:
    $key_2020 = { 77 52 [2] 45 70 [2] 43 45 [2] 6d 45 [2] 52 59 }

  condition:
    any of them
}