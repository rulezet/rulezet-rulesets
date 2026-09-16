rule TTP_XOR_WriteProcessMemory_73fc {
  strings:
    $key_73fc = { 24 8e [2] 16 ac [2] 10 99 [2] 3e 99 [2] 01 85 }

  condition:
    any of them
}