rule TTP_XOR_WriteProcessMemory_74fc {
  strings:
    $key_74fc = { 23 8e [2] 11 ac [2] 17 99 [2] 39 99 [2] 06 85 }

  condition:
    any of them
}