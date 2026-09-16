rule TTP_XOR_WriteProcessMemory_70fc {
  strings:
    $key_70fc = { 27 8e [2] 15 ac [2] 13 99 [2] 3d 99 [2] 02 85 }

  condition:
    any of them
}