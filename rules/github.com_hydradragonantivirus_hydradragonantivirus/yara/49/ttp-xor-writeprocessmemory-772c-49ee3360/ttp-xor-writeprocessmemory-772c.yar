rule TTP_XOR_WriteProcessMemory_772c {
  strings:
    $key_772c = { 20 5e [2] 12 7c [2] 14 49 [2] 3a 49 [2] 05 55 }

  condition:
    any of them
}