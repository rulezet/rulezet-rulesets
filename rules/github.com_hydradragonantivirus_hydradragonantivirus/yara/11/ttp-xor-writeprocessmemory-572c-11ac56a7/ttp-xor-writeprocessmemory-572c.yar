rule TTP_XOR_WriteProcessMemory_572c {
  strings:
    $key_572c = { 00 5e [2] 32 7c [2] 34 49 [2] 1a 49 [2] 25 55 }

  condition:
    any of them
}