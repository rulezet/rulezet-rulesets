rule TTP_XOR_WriteProcessMemory_3a08 {
  strings:
    $key_3a08 = { 6d 7a [2] 5f 58 [2] 59 6d [2] 77 6d [2] 48 71 }

  condition:
    any of them
}