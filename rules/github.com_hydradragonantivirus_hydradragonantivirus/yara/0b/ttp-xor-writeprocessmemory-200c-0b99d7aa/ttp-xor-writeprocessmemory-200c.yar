rule TTP_XOR_WriteProcessMemory_200c {
  strings:
    $key_200c = { 77 7e [2] 45 5c [2] 43 69 [2] 6d 69 [2] 52 75 }

  condition:
    any of them
}