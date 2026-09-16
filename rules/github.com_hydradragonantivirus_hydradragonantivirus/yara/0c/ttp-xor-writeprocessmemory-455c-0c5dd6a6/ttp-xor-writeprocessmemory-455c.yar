rule TTP_XOR_WriteProcessMemory_455c {
  strings:
    $key_455c = { 12 2e [2] 20 0c [2] 26 39 [2] 08 39 [2] 37 25 }

  condition:
    any of them
}