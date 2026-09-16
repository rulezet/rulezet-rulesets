rule TTP_XOR_WriteProcessMemory_30fc {
  strings:
    $key_30fc = { 67 8e [2] 55 ac [2] 53 99 [2] 7d 99 [2] 42 85 }

  condition:
    any of them
}