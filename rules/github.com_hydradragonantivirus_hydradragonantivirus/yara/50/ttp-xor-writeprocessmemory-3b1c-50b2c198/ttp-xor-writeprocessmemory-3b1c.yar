rule TTP_XOR_WriteProcessMemory_3b1c {
  strings:
    $key_3b1c = { 6c 6e [2] 5e 4c [2] 58 79 [2] 76 79 [2] 49 65 }

  condition:
    any of them
}