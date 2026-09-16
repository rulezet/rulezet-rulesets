rule TTP_XOR_WriteProcessMemory_77fc {
  strings:
    $key_77fc = { 20 8e [2] 12 ac [2] 14 99 [2] 3a 99 [2] 05 85 }

  condition:
    any of them
}