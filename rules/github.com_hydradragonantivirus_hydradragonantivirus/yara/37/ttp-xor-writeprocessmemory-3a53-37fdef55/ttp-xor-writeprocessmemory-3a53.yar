rule TTP_XOR_WriteProcessMemory_3a53 {
  strings:
    $key_3a53 = { 6d 21 [2] 5f 03 [2] 59 36 [2] 77 36 [2] 48 2a }

  condition:
    any of them
}