rule TTP_XOR_WriteProcessMemory_1269 {
  strings:
    $key_1269 = { 45 1b [2] 77 39 [2] 71 0c [2] 5f 0c [2] 60 10 }

  condition:
    any of them
}