rule TTP_XOR_WriteProcessMemory_1d0c {
  strings:
    $key_1d0c = { 4a 7e [2] 78 5c [2] 7e 69 [2] 50 69 [2] 6f 75 }

  condition:
    any of them
}