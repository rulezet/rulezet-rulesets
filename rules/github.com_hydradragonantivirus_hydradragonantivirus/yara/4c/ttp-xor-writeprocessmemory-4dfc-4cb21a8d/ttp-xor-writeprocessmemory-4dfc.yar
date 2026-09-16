rule TTP_XOR_WriteProcessMemory_4dfc {
  strings:
    $key_4dfc = { 1a 8e [2] 28 ac [2] 2e 99 [2] 00 99 [2] 3f 85 }

  condition:
    any of them
}