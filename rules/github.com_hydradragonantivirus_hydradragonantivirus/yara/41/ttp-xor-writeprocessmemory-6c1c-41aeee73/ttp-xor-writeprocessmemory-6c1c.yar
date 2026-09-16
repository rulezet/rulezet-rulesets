rule TTP_XOR_WriteProcessMemory_6c1c {
  strings:
    $key_6c1c = { 3b 6e [2] 09 4c [2] 0f 79 [2] 21 79 [2] 1e 65 }

  condition:
    any of them
}