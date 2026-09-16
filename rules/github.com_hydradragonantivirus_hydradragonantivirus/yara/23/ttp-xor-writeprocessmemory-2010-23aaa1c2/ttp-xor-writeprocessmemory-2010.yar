rule TTP_XOR_WriteProcessMemory_2010 {
  strings:
    $key_2010 = { 77 62 [2] 45 40 [2] 43 75 [2] 6d 75 [2] 52 69 }

  condition:
    any of them
}