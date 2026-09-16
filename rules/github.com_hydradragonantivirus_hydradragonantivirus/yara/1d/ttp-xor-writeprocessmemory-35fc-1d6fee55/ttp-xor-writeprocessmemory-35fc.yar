rule TTP_XOR_WriteProcessMemory_35fc {
  strings:
    $key_35fc = { 62 8e [2] 50 ac [2] 56 99 [2] 78 99 [2] 47 85 }

  condition:
    any of them
}