rule TTP_XOR_WriteProcessMemory_0539 {
  strings:
    $key_0539 = { 52 4b [2] 60 69 [2] 66 5c [2] 48 5c [2] 77 40 }

  condition:
    any of them
}