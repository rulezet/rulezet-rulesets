rule TTP_XOR_WriteProcessMemory_756c {
  strings:
    $key_756c = { 22 1e [2] 10 3c [2] 16 09 [2] 38 09 [2] 07 15 }

  condition:
    any of them
}