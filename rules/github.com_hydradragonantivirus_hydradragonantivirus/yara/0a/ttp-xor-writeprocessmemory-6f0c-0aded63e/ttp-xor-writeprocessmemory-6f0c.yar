rule TTP_XOR_WriteProcessMemory_6f0c {
  strings:
    $key_6f0c = { 38 7e [2] 0a 5c [2] 0c 69 [2] 22 69 [2] 1d 75 }

  condition:
    any of them
}