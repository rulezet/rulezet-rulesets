rule TTP_XOR_WriteProcessMemory_4739 {
  strings:
    $key_4739 = { 10 4b [2] 22 69 [2] 24 5c [2] 0a 5c [2] 35 40 }

  condition:
    any of them
}