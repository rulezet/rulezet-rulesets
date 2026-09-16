rule TTP_XOR_WriteProcessMemory_45fc {
  strings:
    $key_45fc = { 12 8e [2] 20 ac [2] 26 99 [2] 08 99 [2] 37 85 }

  condition:
    any of them
}