rule TTP_XOR_WriteProcessMemory_d01c {
  strings:
    $key_d01c = { 87 6e [2] b5 4c [2] b3 79 [2] 9d 79 [2] a2 65 }

  condition:
    any of them
}