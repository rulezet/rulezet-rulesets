rule TTP_XOR_WriteProcessMemory_2029 {
  strings:
    $key_2029 = { 77 5b [2] 45 79 [2] 43 4c [2] 6d 4c [2] 52 50 }

  condition:
    any of them
}