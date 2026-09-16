rule TTP_XOR_WriteProcessMemory_3a69 {
  strings:
    $key_3a69 = { 6d 1b [2] 5f 39 [2] 59 0c [2] 77 0c [2] 48 10 }

  condition:
    any of them
}