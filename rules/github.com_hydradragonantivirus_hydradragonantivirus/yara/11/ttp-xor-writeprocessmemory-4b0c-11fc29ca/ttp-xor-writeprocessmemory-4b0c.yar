rule TTP_XOR_WriteProcessMemory_4b0c {
  strings:
    $key_4b0c = { 1c 7e [2] 2e 5c [2] 28 69 [2] 06 69 [2] 39 75 }

  condition:
    any of them
}