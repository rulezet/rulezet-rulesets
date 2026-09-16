rule TTP_XOR_WriteProcessMemory_240c {
  strings:
    $key_240c = { 73 7e [2] 41 5c [2] 47 69 [2] 69 69 [2] 56 75 }

  condition:
    any of them
}