rule TTP_XOR_WriteProcessMemory_3c1c {
  strings:
    $key_3c1c = { 6b 6e [2] 59 4c [2] 5f 79 [2] 71 79 [2] 4e 65 }

  condition:
    any of them
}