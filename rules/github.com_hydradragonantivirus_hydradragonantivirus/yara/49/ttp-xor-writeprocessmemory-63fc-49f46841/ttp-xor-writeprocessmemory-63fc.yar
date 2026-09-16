rule TTP_XOR_WriteProcessMemory_63fc {
  strings:
    $key_63fc = { 34 8e [2] 06 ac [2] 00 99 [2] 2e 99 [2] 11 85 }

  condition:
    any of them
}