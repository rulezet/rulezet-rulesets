rule TTP_XOR_WriteProcessMemory_3a31 {
  strings:
    $key_3a31 = { 6d 43 [2] 5f 61 [2] 59 54 [2] 77 54 [2] 48 48 }

  condition:
    any of them
}