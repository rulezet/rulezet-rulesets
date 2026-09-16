rule TTP_XOR_WriteProcessMemory_2079 {
  strings:
    $key_2079 = { 77 0b [2] 45 29 [2] 43 1c [2] 6d 1c [2] 52 00 }

  condition:
    any of them
}