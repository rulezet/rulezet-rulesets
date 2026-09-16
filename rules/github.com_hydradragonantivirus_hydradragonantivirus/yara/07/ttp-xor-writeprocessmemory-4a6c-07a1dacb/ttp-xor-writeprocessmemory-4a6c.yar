rule TTP_XOR_WriteProcessMemory_4a6c {
  strings:
    $key_4a6c = { 1d 1e [2] 2f 3c [2] 29 09 [2] 07 09 [2] 38 15 }

  condition:
    any of them
}