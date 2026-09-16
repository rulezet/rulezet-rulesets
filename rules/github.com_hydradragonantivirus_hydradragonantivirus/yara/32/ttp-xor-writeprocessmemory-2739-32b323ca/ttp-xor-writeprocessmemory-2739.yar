rule TTP_XOR_WriteProcessMemory_2739 {
  strings:
    $key_2739 = { 70 4b [2] 42 69 [2] 44 5c [2] 6a 5c [2] 55 40 }

  condition:
    any of them
}