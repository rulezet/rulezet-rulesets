rule TTP_XOR_WriteProcessMemory_3c4c {
  strings:
    $key_3c4c = { 6b 3e [2] 59 1c [2] 5f 29 [2] 71 29 [2] 4e 35 }

  condition:
    any of them
}