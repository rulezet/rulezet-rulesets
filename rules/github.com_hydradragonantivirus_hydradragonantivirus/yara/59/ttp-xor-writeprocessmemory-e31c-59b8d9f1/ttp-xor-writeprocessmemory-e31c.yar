rule TTP_XOR_WriteProcessMemory_e31c {
  strings:
    $key_e31c = { b4 6e [2] 86 4c [2] 80 79 [2] ae 79 [2] 91 65 }

  condition:
    any of them
}