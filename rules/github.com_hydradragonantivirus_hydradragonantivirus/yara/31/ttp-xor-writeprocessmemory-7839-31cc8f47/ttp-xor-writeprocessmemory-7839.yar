rule TTP_XOR_WriteProcessMemory_7839 {
  strings:
    $key_7839 = { 2f 4b [2] 1d 69 [2] 1b 5c [2] 35 5c [2] 0a 40 }

  condition:
    any of them
}