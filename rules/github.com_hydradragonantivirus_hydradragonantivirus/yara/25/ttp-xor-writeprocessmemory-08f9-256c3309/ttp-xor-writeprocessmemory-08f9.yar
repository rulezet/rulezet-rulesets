rule TTP_XOR_WriteProcessMemory_08f9 {
  strings:
    $key_08f9 = { 5f 8b [2] 6d a9 [2] 6b 9c [2] 45 9c [2] 7a 80 }

  condition:
    any of them
}