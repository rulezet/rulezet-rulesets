rule TTP_XOR_WriteProcessMemory_2011 {
  strings:
    $key_2011 = { 77 63 [2] 45 41 [2] 43 74 [2] 6d 74 [2] 52 68 }

  condition:
    any of them
}