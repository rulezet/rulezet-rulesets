rule TTP_XOR_WriteProcessMemory_4b3c {
  strings:
    $key_4b3c = { 1c 4e [2] 2e 6c [2] 28 59 [2] 06 59 [2] 39 45 }

  condition:
    any of them
}