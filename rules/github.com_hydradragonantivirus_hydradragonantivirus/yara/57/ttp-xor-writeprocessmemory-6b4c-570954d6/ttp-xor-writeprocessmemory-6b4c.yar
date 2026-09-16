rule TTP_XOR_WriteProcessMemory_6b4c {
  strings:
    $key_6b4c = { 3c 3e [2] 0e 1c [2] 08 29 [2] 26 29 [2] 19 35 }

  condition:
    any of them
}