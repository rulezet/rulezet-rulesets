rule TTP_XOR_WriteProcessMemory_3c6c {
  strings:
    $key_3c6c = { 6b 1e [2] 59 3c [2] 5f 09 [2] 71 09 [2] 4e 15 }

  condition:
    any of them
}