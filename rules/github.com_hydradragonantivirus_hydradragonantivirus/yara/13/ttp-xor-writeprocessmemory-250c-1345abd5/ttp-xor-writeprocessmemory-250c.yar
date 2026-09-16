rule TTP_XOR_WriteProcessMemory_250c {
  strings:
    $key_250c = { 72 7e [2] 40 5c [2] 46 69 [2] 68 69 [2] 57 75 }

  condition:
    any of them
}