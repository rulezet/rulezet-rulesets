rule TTP_XOR_WriteProcessMemory_7329 {
  strings:
    $key_7329 = { 24 5b [2] 16 79 [2] 10 4c [2] 3e 4c [2] 01 50 }

  condition:
    any of them
}