rule TTP_XOR_WriteProcessMemory_1d39 {
  strings:
    $key_1d39 = { 4a 4b [2] 78 69 [2] 7e 5c [2] 50 5c [2] 6f 40 }

  condition:
    any of them
}