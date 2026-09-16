rule TTP_XOR_WriteProcessMemory_3b6c {
  strings:
    $key_3b6c = { 6c 1e [2] 5e 3c [2] 58 09 [2] 76 09 [2] 49 15 }

  condition:
    any of them
}