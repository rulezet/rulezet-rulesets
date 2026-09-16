rule TTP_XOR_WriteProcessMemory_1239 {
  strings:
    $key_1239 = { 45 4b [2] 77 69 [2] 71 5c [2] 5f 5c [2] 60 40 }

  condition:
    any of them
}