rule TTP_XOR_WriteProcessMemory_445c {
  strings:
    $key_445c = { 13 2e [2] 21 0c [2] 27 39 [2] 09 39 [2] 36 25 }

  condition:
    any of them
}