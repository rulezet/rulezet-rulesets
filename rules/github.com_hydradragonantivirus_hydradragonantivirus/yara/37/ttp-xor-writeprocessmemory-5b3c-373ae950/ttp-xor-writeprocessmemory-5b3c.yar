rule TTP_XOR_WriteProcessMemory_5b3c {
  strings:
    $key_5b3c = { 0c 4e [2] 3e 6c [2] 38 59 [2] 16 59 [2] 29 45 }

  condition:
    any of them
}