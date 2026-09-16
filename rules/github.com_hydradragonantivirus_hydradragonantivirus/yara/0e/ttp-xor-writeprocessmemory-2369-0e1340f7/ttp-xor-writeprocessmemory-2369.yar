rule TTP_XOR_WriteProcessMemory_2369 {
  strings:
    $key_2369 = { 74 1b [2] 46 39 [2] 40 0c [2] 6e 0c [2] 51 10 }

  condition:
    any of them
}