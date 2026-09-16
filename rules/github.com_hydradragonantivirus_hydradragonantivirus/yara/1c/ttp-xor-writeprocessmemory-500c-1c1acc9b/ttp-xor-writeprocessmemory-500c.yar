rule TTP_XOR_WriteProcessMemory_500c {
  strings:
    $key_500c = { 07 7e [2] 35 5c [2] 33 69 [2] 1d 69 [2] 22 75 }

  condition:
    any of them
}