rule TTP_XOR_WriteProcessMemory_0529 {
  strings:
    $key_0529 = { 52 5b [2] 60 79 [2] 66 4c [2] 48 4c [2] 77 50 }

  condition:
    any of them
}