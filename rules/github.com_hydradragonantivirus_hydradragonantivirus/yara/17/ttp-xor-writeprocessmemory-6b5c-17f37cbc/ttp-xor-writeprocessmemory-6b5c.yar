rule TTP_XOR_WriteProcessMemory_6b5c {
  strings:
    $key_6b5c = { 3c 2e [2] 0e 0c [2] 08 39 [2] 26 39 [2] 19 25 }

  condition:
    any of them
}