rule TTP_XOR_WriteProcessMemory_402c {
  strings:
    $key_402c = { 17 5e [2] 25 7c [2] 23 49 [2] 0d 49 [2] 32 55 }

  condition:
    any of them
}