rule TTP_XOR_WriteProcessMemory_532c {
  strings:
    $key_532c = { 04 5e [2] 36 7c [2] 30 49 [2] 1e 49 [2] 21 55 }

  condition:
    any of them
}