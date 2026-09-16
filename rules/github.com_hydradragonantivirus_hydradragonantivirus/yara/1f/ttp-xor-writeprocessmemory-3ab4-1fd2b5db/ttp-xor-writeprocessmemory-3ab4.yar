rule TTP_XOR_WriteProcessMemory_3ab4 {
  strings:
    $key_3ab4 = { 6d c6 [2] 5f e4 [2] 59 d1 [2] 77 d1 [2] 48 cd }

  condition:
    any of them
}