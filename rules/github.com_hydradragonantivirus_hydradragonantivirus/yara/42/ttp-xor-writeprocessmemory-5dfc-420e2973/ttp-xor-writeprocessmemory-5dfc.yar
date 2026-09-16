rule TTP_XOR_WriteProcessMemory_5dfc {
  strings:
    $key_5dfc = { 0a 8e [2] 38 ac [2] 3e 99 [2] 10 99 [2] 2f 85 }

  condition:
    any of them
}