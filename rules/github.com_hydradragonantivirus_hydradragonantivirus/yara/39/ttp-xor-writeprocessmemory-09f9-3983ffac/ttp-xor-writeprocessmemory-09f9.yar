rule TTP_XOR_WriteProcessMemory_09f9 {
  strings:
    $key_09f9 = { 5e 8b [2] 6c a9 [2] 6a 9c [2] 44 9c [2] 7b 80 }

  condition:
    any of them
}