rule TTP_XOR_WriteProcessMemory_22e9 {
  strings:
    $key_22e9 = { 75 9b [2] 47 b9 [2] 41 8c [2] 6f 8c [2] 50 90 }

  condition:
    any of them
}