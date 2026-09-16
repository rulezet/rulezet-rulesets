rule TTP_XOR_WriteProcessMemory_7459 {
  strings:
    $key_7459 = { 23 2b [2] 11 09 [2] 17 3c [2] 39 3c [2] 06 20 }

  condition:
    any of them
}