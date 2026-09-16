rule TTP_XOR_WriteProcessMemory_29f9 {
  strings:
    $key_29f9 = { 7e 8b [2] 4c a9 [2] 4a 9c [2] 64 9c [2] 5b 80 }

  condition:
    any of them
}