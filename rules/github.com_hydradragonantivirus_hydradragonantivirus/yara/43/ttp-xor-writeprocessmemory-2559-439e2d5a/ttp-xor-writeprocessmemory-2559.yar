rule TTP_XOR_WriteProcessMemory_2559 {
  strings:
    $key_2559 = { 72 2b [2] 40 09 [2] 46 3c [2] 68 3c [2] 57 20 }

  condition:
    any of them
}