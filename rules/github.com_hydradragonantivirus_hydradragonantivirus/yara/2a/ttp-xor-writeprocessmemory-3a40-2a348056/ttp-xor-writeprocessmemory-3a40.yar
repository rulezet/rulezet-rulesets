rule TTP_XOR_WriteProcessMemory_3a40 {
  strings:
    $key_3a40 = { 6d 32 [2] 5f 10 [2] 59 25 [2] 77 25 [2] 48 39 }

  condition:
    any of them
}