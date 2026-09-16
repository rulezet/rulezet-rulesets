rule TTP_XOR_WriteProcessMemory_42f9 {
  strings:
    $key_42f9 = { 15 8b [2] 27 a9 [2] 21 9c [2] 0f 9c [2] 30 80 }

  condition:
    any of them
}