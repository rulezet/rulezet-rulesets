rule TTP_XOR_WriteProcessMemory_231c {
  strings:
    $key_231c = { 74 6e [2] 46 4c [2] 40 79 [2] 6e 79 [2] 51 65 }

  condition:
    any of them
}