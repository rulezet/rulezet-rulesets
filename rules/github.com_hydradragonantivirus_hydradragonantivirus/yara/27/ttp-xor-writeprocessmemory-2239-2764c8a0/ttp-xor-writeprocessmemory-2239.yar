rule TTP_XOR_WriteProcessMemory_2239 {
  strings:
    $key_2239 = { 75 4b [2] 47 69 [2] 41 5c [2] 6f 5c [2] 50 40 }

  condition:
    any of them
}