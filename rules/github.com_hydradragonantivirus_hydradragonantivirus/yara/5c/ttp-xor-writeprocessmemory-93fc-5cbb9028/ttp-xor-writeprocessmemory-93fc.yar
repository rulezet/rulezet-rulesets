rule TTP_XOR_WriteProcessMemory_93fc {
  strings:
    $key_93fc = { c4 8e [2] f6 ac [2] f0 99 [2] de 99 [2] e1 85 }

  condition:
    any of them
}