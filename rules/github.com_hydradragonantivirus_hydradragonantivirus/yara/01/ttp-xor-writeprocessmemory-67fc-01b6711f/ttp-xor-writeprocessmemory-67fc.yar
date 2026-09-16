rule TTP_XOR_WriteProcessMemory_67fc {
  strings:
    $key_67fc = { 30 8e [2] 02 ac [2] 04 99 [2] 2a 99 [2] 15 85 }

  condition:
    any of them
}