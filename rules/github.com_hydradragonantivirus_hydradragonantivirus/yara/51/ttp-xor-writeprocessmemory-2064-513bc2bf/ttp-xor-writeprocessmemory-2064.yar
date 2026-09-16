rule TTP_XOR_WriteProcessMemory_2064 {
  strings:
    $key_2064 = { 77 16 [2] 45 34 [2] 43 01 [2] 6d 01 [2] 52 1d }

  condition:
    any of them
}