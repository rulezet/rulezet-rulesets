rule TTP_XOR_WriteProcessMemory_5c4c {
  strings:
    $key_5c4c = { 0b 3e [2] 39 1c [2] 3f 29 [2] 11 29 [2] 2e 35 }

  condition:
    any of them
}