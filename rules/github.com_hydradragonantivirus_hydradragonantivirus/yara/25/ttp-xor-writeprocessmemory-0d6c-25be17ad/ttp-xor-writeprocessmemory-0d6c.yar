rule TTP_XOR_WriteProcessMemory_0d6c {
  strings:
    $key_0d6c = { 5a 1e [2] 68 3c [2] 6e 09 [2] 40 09 [2] 7f 15 }

  condition:
    any of them
}