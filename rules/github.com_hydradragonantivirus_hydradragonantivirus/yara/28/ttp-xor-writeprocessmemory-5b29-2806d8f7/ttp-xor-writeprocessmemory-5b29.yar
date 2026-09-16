rule TTP_XOR_WriteProcessMemory_5b29 {
  strings:
    $key_5b29 = { 0c 5b [2] 3e 79 [2] 38 4c [2] 16 4c [2] 29 50 }

  condition:
    any of them
}