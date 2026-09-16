rule TTP_XOR_WriteProcessMemory_395c {
  strings:
    $key_395c = { 6e 2e [2] 5c 0c [2] 5a 39 [2] 74 39 [2] 4b 25 }

  condition:
    any of them
}