rule TTP_XOR_WriteProcessMemory_2006 {
  strings:
    $key_2006 = { 77 74 [2] 45 56 [2] 43 63 [2] 6d 63 [2] 52 7f }

  condition:
    any of them
}