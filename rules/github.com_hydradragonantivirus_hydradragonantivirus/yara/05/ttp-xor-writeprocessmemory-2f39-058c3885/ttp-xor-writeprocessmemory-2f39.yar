rule TTP_XOR_WriteProcessMemory_2f39 {
  strings:
    $key_2f39 = { 78 4b [2] 4a 69 [2] 4c 5c [2] 62 5c [2] 5d 40 }

  condition:
    any of them
}