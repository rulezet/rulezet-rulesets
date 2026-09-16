rule TTP_XOR_WriteProcessMemory_4b6c {
  strings:
    $key_4b6c = { 1c 1e [2] 2e 3c [2] 28 09 [2] 06 09 [2] 39 15 }

  condition:
    any of them
}