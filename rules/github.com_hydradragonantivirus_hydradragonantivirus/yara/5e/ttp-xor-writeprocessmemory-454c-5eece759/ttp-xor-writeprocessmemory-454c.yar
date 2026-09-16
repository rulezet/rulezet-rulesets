rule TTP_XOR_WriteProcessMemory_454c {
  strings:
    $key_454c = { 12 3e [2] 20 1c [2] 26 29 [2] 08 29 [2] 37 35 }

  condition:
    any of them
}