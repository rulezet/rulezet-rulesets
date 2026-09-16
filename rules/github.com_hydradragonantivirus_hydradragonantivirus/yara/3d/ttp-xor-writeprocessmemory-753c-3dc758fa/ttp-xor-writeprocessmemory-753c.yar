rule TTP_XOR_WriteProcessMemory_753c {
  strings:
    $key_753c = { 22 4e [2] 10 6c [2] 16 59 [2] 38 59 [2] 07 45 }

  condition:
    any of them
}