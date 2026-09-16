rule TTP_XOR_WriteProcessMemory_19f9 {
  strings:
    $key_19f9 = { 4e 8b [2] 7c a9 [2] 7a 9c [2] 54 9c [2] 6b 80 }

  condition:
    any of them
}