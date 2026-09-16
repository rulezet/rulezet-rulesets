rule TTP_XOR_WriteProcessMemory_3aa0 {
  strings:
    $key_3aa0 = { 6d d2 [2] 5f f0 [2] 59 c5 [2] 77 c5 [2] 48 d9 }

  condition:
    any of them
}