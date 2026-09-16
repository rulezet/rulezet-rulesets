rule TTP_XOR_WriteProcessMemory_3a42 {
  strings:
    $key_3a42 = { 6d 30 [2] 5f 12 [2] 59 27 [2] 77 27 [2] 48 3b }

  condition:
    any of them
}