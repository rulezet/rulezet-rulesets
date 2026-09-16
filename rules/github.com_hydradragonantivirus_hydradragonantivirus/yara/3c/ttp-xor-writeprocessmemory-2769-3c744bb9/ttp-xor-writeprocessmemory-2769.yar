rule TTP_XOR_WriteProcessMemory_2769 {
  strings:
    $key_2769 = { 70 1b [2] 42 39 [2] 44 0c [2] 6a 0c [2] 55 10 }

  condition:
    any of them
}