rule TTP_XOR_WriteProcessMemory_60fc {
  strings:
    $key_60fc = { 37 8e [2] 05 ac [2] 03 99 [2] 2d 99 [2] 12 85 }

  condition:
    any of them
}