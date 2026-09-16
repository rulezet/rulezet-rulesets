rule TTP_XOR_WriteProcessMemory_7f4c {
  strings:
    $key_7f4c = { 28 3e [2] 1a 1c [2] 1c 29 [2] 32 29 [2] 0d 35 }

  condition:
    any of them
}