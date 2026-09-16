rule TTP_XOR_WriteProcessMemory_1c1c {
  strings:
    $key_1c1c = { 4b 6e [2] 79 4c [2] 7f 79 [2] 51 79 [2] 6e 65 }

  condition:
    any of them
}