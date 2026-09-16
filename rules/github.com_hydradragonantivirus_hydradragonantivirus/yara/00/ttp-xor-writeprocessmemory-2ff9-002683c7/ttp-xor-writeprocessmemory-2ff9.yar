rule TTP_XOR_WriteProcessMemory_2ff9 {
  strings:
    $key_2ff9 = { 78 8b [2] 4a a9 [2] 4c 9c [2] 62 9c [2] 5d 80 }

  condition:
    any of them
}