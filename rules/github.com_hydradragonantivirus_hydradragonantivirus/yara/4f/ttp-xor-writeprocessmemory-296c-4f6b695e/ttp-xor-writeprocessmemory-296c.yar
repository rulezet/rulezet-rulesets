rule TTP_XOR_WriteProcessMemory_296c {
  strings:
    $key_296c = { 7e 1e [2] 4c 3c [2] 4a 09 [2] 64 09 [2] 5b 15 }

  condition:
    any of them
}