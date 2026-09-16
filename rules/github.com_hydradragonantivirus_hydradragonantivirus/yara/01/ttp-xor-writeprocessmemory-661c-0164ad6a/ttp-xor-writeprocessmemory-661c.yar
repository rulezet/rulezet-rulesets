rule TTP_XOR_WriteProcessMemory_661c {
  strings:
    $key_661c = { 31 6e [2] 03 4c [2] 05 79 [2] 2b 79 [2] 14 65 }

  condition:
    any of them
}