rule TTP_XOR_WriteProcessMemory_2dfc {
  strings:
    $key_2dfc = { 7a 8e [2] 48 ac [2] 4e 99 [2] 60 99 [2] 5f 85 }

  condition:
    any of them
}