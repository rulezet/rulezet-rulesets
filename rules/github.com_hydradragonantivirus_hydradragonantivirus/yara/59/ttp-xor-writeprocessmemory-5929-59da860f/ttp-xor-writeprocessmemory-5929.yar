rule TTP_XOR_WriteProcessMemory_5929 {
  strings:
    $key_5929 = { 0e 5b [2] 3c 79 [2] 3a 4c [2] 14 4c [2] 2b 50 }

  condition:
    any of them
}