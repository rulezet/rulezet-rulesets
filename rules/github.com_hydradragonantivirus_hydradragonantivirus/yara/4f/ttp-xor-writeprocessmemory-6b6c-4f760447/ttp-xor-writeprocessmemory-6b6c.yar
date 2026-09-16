rule TTP_XOR_WriteProcessMemory_6b6c {
  strings:
    $key_6b6c = { 3c 1e [2] 0e 3c [2] 08 09 [2] 26 09 [2] 19 15 }

  condition:
    any of them
}