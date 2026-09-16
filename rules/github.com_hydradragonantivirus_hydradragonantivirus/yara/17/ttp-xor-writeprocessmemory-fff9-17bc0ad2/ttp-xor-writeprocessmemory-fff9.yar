rule TTP_XOR_WriteProcessMemory_fff9 {
  strings:
    $key_fff9 = { a8 8b [2] 9a a9 [2] 9c 9c [2] b2 9c [2] 8d 80 }

  condition:
    any of them
}