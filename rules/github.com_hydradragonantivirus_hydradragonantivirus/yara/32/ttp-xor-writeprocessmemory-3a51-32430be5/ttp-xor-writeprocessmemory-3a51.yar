rule TTP_XOR_WriteProcessMemory_3a51 {
  strings:
    $key_3a51 = { 6d 23 [2] 5f 01 [2] 59 34 [2] 77 34 [2] 48 28 }

  condition:
    any of them
}