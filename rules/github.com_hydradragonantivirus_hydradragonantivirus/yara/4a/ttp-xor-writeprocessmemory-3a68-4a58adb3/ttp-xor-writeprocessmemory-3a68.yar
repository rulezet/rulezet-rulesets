rule TTP_XOR_WriteProcessMemory_3a68 {
  strings:
    $key_3a68 = { 6d 1a [2] 5f 38 [2] 59 0d [2] 77 0d [2] 48 11 }

  condition:
    any of them
}