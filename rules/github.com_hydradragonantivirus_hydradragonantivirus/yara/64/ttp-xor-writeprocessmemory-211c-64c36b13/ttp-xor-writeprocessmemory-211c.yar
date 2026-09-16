rule TTP_XOR_WriteProcessMemory_211c {
  strings:
    $key_211c = { 76 6e [2] 44 4c [2] 42 79 [2] 6c 79 [2] 53 65 }

  condition:
    any of them
}