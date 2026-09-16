rule TTP_XOR_WriteProcessMemory_5559 {
  strings:
    $key_5559 = { 02 2b [2] 30 09 [2] 36 3c [2] 18 3c [2] 27 20 }

  condition:
    any of them
}