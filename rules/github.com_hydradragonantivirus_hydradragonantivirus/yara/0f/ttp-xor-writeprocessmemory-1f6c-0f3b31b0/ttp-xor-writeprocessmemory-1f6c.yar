rule TTP_XOR_WriteProcessMemory_1f6c {
  strings:
    $key_1f6c = { 48 1e [2] 7a 3c [2] 7c 09 [2] 52 09 [2] 6d 15 }

  condition:
    any of them
}