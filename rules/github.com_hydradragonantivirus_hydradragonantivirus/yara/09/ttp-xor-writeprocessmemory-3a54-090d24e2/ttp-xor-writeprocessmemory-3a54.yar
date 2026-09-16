rule TTP_XOR_WriteProcessMemory_3a54 {
  strings:
    $key_3a54 = { 6d 26 [2] 5f 04 [2] 59 31 [2] 77 31 [2] 48 2d }

  condition:
    any of them
}