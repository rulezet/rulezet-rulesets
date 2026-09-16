rule TTP_XOR_WriteProcessMemory_d21c {
  strings:
    $key_d21c = { 85 6e [2] b7 4c [2] b1 79 [2] 9f 79 [2] a0 65 }

  condition:
    any of them
}