rule TTP_XOR_WriteProcessMemory_c11c {
  strings:
    $key_c11c = { 96 6e [2] a4 4c [2] a2 79 [2] 8c 79 [2] b3 65 }

  condition:
    any of them
}