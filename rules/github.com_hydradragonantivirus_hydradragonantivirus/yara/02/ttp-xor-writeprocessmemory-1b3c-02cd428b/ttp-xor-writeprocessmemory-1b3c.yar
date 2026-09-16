rule TTP_XOR_WriteProcessMemory_1b3c {
  strings:
    $key_1b3c = { 4c 4e [2] 7e 6c [2] 78 59 [2] 56 59 [2] 69 45 }

  condition:
    any of them
}