rule TTP_XOR_WriteProcessMemory_82fc {
  strings:
    $key_82fc = { d5 8e [2] e7 ac [2] e1 99 [2] cf 99 [2] f0 85 }

  condition:
    any of them
}