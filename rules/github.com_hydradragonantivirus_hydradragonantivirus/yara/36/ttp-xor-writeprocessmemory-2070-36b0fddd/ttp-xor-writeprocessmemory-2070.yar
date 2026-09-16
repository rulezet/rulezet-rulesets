rule TTP_XOR_WriteProcessMemory_2070 {
  strings:
    $key_2070 = { 77 02 [2] 45 20 [2] 43 15 [2] 6d 15 [2] 52 09 }

  condition:
    any of them
}