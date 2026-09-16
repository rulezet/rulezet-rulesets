rule TTP_XOR_WriteProcessMemory_5d0c {
  strings:
    $key_5d0c = { 0a 7e [2] 38 5c [2] 3e 69 [2] 10 69 [2] 2f 75 }

  condition:
    any of them
}