rule TTP_XOR_WriteProcessMemory_3b29 {
  strings:
    $key_3b29 = { 6c 5b [2] 5e 79 [2] 58 4c [2] 76 4c [2] 49 50 }

  condition:
    any of them
}