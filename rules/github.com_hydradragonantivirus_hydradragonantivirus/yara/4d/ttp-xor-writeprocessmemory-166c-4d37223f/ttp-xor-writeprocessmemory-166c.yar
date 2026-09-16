rule TTP_XOR_WriteProcessMemory_166c {
  strings:
    $key_166c = { 41 1e [2] 73 3c [2] 75 09 [2] 5b 09 [2] 64 15 }

  condition:
    any of them
}