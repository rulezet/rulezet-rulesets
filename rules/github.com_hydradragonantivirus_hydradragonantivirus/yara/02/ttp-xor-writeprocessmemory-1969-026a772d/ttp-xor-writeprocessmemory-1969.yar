rule TTP_XOR_WriteProcessMemory_1969 {
  strings:
    $key_1969 = { 4e 1b [2] 7c 39 [2] 7a 0c [2] 54 0c [2] 6b 10 }

  condition:
    any of them
}