rule TTP_XOR_WriteProcessMemory_2359 {
  strings:
    $key_2359 = { 74 2b [2] 46 09 [2] 40 3c [2] 6e 3c [2] 51 20 }

  condition:
    any of them
}