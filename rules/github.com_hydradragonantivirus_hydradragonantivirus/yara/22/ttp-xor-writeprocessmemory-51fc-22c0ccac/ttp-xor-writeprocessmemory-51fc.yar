rule TTP_XOR_WriteProcessMemory_51fc {
  strings:
    $key_51fc = { 06 8e [2] 34 ac [2] 32 99 [2] 1c 99 [2] 23 85 }

  condition:
    any of them
}