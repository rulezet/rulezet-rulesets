rule TTP_XOR_WriteProcessMemory_541c {
  strings:
    $key_541c = { 03 6e [2] 31 4c [2] 37 79 [2] 19 79 [2] 26 65 }

  condition:
    any of them
}