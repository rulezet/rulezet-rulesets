rule TTP_XOR_WriteProcessMemory_296b {
  strings:
    $key_296b = { 7e 19 [2] 4c 3b [2] 4a 0e [2] 64 0e [2] 5b 12 }

  condition:
    any of them
}