rule TTP_XOR_WriteProcessMemory_662c {
  strings:
    $key_662c = { 31 5e [2] 03 7c [2] 05 49 [2] 2b 49 [2] 14 55 }

  condition:
    any of them
}