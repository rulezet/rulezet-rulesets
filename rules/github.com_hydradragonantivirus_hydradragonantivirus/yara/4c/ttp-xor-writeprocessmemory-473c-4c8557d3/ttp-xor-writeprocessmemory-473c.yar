rule TTP_XOR_WriteProcessMemory_473c {
  strings:
    $key_473c = { 10 4e [2] 22 6c [2] 24 59 [2] 0a 59 [2] 35 45 }

  condition:
    any of them
}