rule TTP_XOR_WriteProcessMemory_4a5c {
  strings:
    $key_4a5c = { 1d 2e [2] 2f 0c [2] 29 39 [2] 07 39 [2] 38 25 }

  condition:
    any of them
}