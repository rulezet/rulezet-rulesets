rule TTP_XOR_WriteProcessMemory_40fc {
  strings:
    $key_40fc = { 17 8e [2] 25 ac [2] 23 99 [2] 0d 99 [2] 32 85 }

  condition:
    any of them
}