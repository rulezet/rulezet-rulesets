rule TTP_XOR_WriteProcessMemory_33fc {
  strings:
    $key_33fc = { 64 8e [2] 56 ac [2] 50 99 [2] 7e 99 [2] 41 85 }

  condition:
    any of them
}