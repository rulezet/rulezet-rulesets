rule TTP_XOR_WriteProcessMemory_161c {
  strings:
    $key_161c = { 41 6e [2] 73 4c [2] 75 79 [2] 5b 79 [2] 64 65 }

  condition:
    any of them
}