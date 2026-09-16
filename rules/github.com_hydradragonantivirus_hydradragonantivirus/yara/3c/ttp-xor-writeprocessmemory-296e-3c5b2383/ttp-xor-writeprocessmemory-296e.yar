rule TTP_XOR_WriteProcessMemory_296e {
  strings:
    $key_296e = { 7e 1c [2] 4c 3e [2] 4a 0b [2] 64 0b [2] 5b 17 }

  condition:
    any of them
}