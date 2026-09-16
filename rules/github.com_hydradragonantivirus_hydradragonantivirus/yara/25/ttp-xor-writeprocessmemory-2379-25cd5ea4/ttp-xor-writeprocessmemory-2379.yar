rule TTP_XOR_WriteProcessMemory_2379 {
  strings:
    $key_2379 = { 74 0b [2] 46 29 [2] 40 1c [2] 6e 1c [2] 51 00 }

  condition:
    any of them
}