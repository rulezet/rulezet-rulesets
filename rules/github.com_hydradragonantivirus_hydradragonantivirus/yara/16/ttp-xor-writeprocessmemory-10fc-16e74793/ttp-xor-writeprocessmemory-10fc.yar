rule TTP_XOR_WriteProcessMemory_10fc {
  strings:
    $key_10fc = { 47 8e [2] 75 ac [2] 73 99 [2] 5d 99 [2] 62 85 }

  condition:
    any of them
}