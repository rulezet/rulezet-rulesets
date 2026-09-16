rule TTP_XOR_WriteProcessMemory_11fc {
  strings:
    $key_11fc = { 46 8e [2] 74 ac [2] 72 99 [2] 5c 99 [2] 63 85 }

  condition:
    any of them
}