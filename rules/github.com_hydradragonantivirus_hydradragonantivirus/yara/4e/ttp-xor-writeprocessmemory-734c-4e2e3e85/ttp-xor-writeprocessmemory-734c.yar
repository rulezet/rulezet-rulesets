rule TTP_XOR_WriteProcessMemory_734c {
  strings:
    $key_734c = { 24 3e [2] 16 1c [2] 10 29 [2] 3e 29 [2] 01 35 }

  condition:
    any of them
}