rule TTP_XOR_WriteProcessMemory_6b29 {
  strings:
    $key_6b29 = { 3c 5b [2] 0e 79 [2] 08 4c [2] 26 4c [2] 19 50 }

  condition:
    any of them
}