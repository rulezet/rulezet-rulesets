rule TTP_XOR_WriteProcessMemory_0c1c {
  strings:
    $key_0c1c = { 5b 6e [2] 69 4c [2] 6f 79 [2] 41 79 [2] 7e 65 }

  condition:
    any of them
}