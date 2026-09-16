rule TTP_XOR_WriteProcessMemory_20fc {
  strings:
    $key_20fc = { 77 8e [2] 45 ac [2] 43 99 [2] 6d 99 [2] 52 85 }

  condition:
    any of them
}