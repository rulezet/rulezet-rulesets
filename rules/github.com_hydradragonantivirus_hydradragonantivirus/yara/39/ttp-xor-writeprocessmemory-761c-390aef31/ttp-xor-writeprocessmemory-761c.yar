rule TTP_XOR_WriteProcessMemory_761c {
  strings:
    $key_761c = { 21 6e [2] 13 4c [2] 15 79 [2] 3b 79 [2] 04 65 }

  condition:
    any of them
}