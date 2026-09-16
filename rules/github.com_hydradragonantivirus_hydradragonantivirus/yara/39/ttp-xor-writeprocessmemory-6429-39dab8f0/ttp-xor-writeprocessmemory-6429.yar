rule TTP_XOR_WriteProcessMemory_6429 {
  strings:
    $key_6429 = { 33 5b [2] 01 79 [2] 07 4c [2] 29 4c [2] 16 50 }

  condition:
    any of them
}