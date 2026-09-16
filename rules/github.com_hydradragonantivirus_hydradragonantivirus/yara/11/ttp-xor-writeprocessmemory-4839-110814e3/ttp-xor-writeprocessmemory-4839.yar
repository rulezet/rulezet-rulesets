rule TTP_XOR_WriteProcessMemory_4839 {
  strings:
    $key_4839 = { 1f 4b [2] 2d 69 [2] 2b 5c [2] 05 5c [2] 3a 40 }

  condition:
    any of them
}