rule TTP_XOR_WriteProcessMemory_3f1c {
  strings:
    $key_3f1c = { 68 6e [2] 5a 4c [2] 5c 79 [2] 72 79 [2] 4d 65 }

  condition:
    any of them
}