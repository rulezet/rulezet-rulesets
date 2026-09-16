rule TTP_XOR_WriteProcessMemory_086c {
  strings:
    $key_086c = { 5f 1e [2] 6d 3c [2] 6b 09 [2] 45 09 [2] 7a 15 }

  condition:
    any of them
}