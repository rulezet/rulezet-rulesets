rule TTP_XOR_WriteProcessMemory_3929 {
  strings:
    $key_3929 = { 6e 5b [2] 5c 79 [2] 5a 4c [2] 74 4c [2] 4b 50 }

  condition:
    any of them
}