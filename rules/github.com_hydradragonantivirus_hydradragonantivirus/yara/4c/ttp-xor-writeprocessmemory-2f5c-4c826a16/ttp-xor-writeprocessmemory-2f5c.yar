rule TTP_XOR_WriteProcessMemory_2f5c {
  strings:
    $key_2f5c = { 78 2e [2] 4a 0c [2] 4c 39 [2] 62 39 [2] 5d 25 }

  condition:
    any of them
}