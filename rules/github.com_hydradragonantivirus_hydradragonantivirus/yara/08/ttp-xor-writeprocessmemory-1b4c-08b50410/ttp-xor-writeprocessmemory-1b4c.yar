rule TTP_XOR_WriteProcessMemory_1b4c {
  strings:
    $key_1b4c = { 4c 3e [2] 7e 1c [2] 78 29 [2] 56 29 [2] 69 35 }

  condition:
    any of them
}