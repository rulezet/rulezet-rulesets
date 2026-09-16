rule TTP_XOR_WriteProcessMemory_14d0 {
  strings:
    $key_14d0 = { 43 a2 [2] 71 80 [2] 77 b5 [2] 59 b5 [2] 66 a9 }

  condition:
    any of them
}