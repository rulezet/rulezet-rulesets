rule TTP_XOR_WriteProcessMemory_235c {
  strings:
    $key_235c = { 74 2e [2] 46 0c [2] 40 39 [2] 6e 39 [2] 51 25 }

  condition:
    any of them
}