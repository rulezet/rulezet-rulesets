rule TTP_XOR_WriteProcessMemory_87fc {
  strings:
    $key_87fc = { d0 8e [2] e2 ac [2] e4 99 [2] ca 99 [2] f5 85 }

  condition:
    any of them
}