rule TTP_XOR_WriteProcessMemory_71fc {
  strings:
    $key_71fc = { 26 8e [2] 14 ac [2] 12 99 [2] 3c 99 [2] 03 85 }

  condition:
    any of them
}