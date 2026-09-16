rule TTP_XOR_WriteProcessMemory_16fc {
  strings:
    $key_16fc = { 41 8e [2] 73 ac [2] 75 99 [2] 5b 99 [2] 64 85 }

  condition:
    any of them
}