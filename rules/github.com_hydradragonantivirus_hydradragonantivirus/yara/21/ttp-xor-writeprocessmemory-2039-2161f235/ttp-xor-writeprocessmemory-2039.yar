rule TTP_XOR_WriteProcessMemory_2039 {
  strings:
    $key_2039 = { 77 4b [2] 45 69 [2] 43 5c [2] 6d 5c [2] 52 40 }

  condition:
    any of them
}