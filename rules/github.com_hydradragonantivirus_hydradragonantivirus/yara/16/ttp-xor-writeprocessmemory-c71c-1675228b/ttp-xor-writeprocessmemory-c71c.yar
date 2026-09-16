rule TTP_XOR_WriteProcessMemory_c71c {
  strings:
    $key_c71c = { 90 6e [2] a2 4c [2] a4 79 [2] 8a 79 [2] b5 65 }

  condition:
    any of them
}