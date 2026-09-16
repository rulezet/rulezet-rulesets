rule TTP_XOR_WriteProcessMemory_53f9 {
  strings:
    $key_53f9 = { 04 8b [2] 36 a9 [2] 30 9c [2] 1e 9c [2] 21 80 }

  condition:
    any of them
}