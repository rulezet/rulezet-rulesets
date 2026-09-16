rule TTP_XOR_WriteProcessMemory_114c {
  strings:
    $key_114c = { 46 3e [2] 74 1c [2] 72 29 [2] 5c 29 [2] 63 35 }

  condition:
    any of them
}