rule TTP_XOR_WriteProcessMemory_3ab5 {
  strings:
    $key_3ab5 = { 6d c7 [2] 5f e5 [2] 59 d0 [2] 77 d0 [2] 48 cc }

  condition:
    any of them
}