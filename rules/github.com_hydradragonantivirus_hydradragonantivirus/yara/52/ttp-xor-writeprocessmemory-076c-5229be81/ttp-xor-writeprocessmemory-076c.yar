rule TTP_XOR_WriteProcessMemory_076c {
  strings:
    $key_076c = { 50 1e [2] 62 3c [2] 64 09 [2] 4a 09 [2] 75 15 }

  condition:
    any of them
}