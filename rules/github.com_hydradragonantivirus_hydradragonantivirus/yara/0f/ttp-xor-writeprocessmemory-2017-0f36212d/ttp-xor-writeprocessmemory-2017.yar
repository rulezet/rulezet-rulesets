rule TTP_XOR_WriteProcessMemory_2017 {
  strings:
    $key_2017 = { 77 65 [2] 45 47 [2] 43 72 [2] 6d 72 [2] 52 6e }

  condition:
    any of them
}