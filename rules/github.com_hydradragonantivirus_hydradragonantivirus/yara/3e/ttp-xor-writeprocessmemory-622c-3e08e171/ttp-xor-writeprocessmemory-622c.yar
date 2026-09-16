rule TTP_XOR_WriteProcessMemory_622c {
  strings:
    $key_622c = { 35 5e [2] 07 7c [2] 01 49 [2] 2f 49 [2] 10 55 }

  condition:
    any of them
}