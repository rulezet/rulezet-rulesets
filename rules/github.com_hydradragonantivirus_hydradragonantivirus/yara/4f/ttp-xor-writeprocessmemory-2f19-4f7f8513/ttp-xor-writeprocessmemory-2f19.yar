rule TTP_XOR_WriteProcessMemory_2f19 {
  strings:
    $key_2f19 = { 78 6b [2] 4a 49 [2] 4c 7c [2] 62 7c [2] 5d 60 }

  condition:
    any of them
}