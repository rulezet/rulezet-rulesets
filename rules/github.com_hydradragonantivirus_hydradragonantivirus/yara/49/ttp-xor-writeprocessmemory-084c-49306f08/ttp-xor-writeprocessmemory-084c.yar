rule TTP_XOR_WriteProcessMemory_084c {
  strings:
    $key_084c = { 5f 3e [2] 6d 1c [2] 6b 29 [2] 45 29 [2] 7a 35 }

  condition:
    any of them
}