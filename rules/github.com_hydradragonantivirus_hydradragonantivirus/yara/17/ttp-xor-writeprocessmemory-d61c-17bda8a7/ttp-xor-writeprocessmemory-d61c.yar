rule TTP_XOR_WriteProcessMemory_d61c {
  strings:
    $key_d61c = { 81 6e [2] b3 4c [2] b5 79 [2] 9b 79 [2] a4 65 }

  condition:
    any of them
}