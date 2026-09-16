rule TTP_XOR_WriteProcessMemory_635c {
  strings:
    $key_635c = { 34 2e [2] 06 0c [2] 00 39 [2] 2e 39 [2] 11 25 }

  condition:
    any of them
}