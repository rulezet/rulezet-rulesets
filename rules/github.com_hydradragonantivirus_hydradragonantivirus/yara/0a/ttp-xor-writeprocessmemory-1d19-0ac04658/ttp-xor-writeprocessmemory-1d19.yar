rule TTP_XOR_WriteProcessMemory_1d19 {
  strings:
    $key_1d19 = { 4a 6b [2] 78 49 [2] 7e 7c [2] 50 7c [2] 6f 60 }

  condition:
    any of them
}