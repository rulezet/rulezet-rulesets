rule TTP_XOR_WriteProcessMemory_47fc {
  strings:
    $key_47fc = { 10 8e [2] 22 ac [2] 24 99 [2] 0a 99 [2] 35 85 }

  condition:
    any of them
}