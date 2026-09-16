rule TTP_XOR_WriteProcessMemory_72fc {
  strings:
    $key_72fc = { 25 8e [2] 17 ac [2] 11 99 [2] 3f 99 [2] 00 85 }

  condition:
    any of them
}